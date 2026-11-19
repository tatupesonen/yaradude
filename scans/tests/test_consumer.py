"""
The live scan socket (/ws/scans/). Channels' own WebsocketCommunicator is in
`channels.testing`, whose package import needs daphne (not a dependency), so
this uses the same asgiref ApplicationCommunicator it is built on.
"""

from __future__ import annotations

import json
from typing import Any
from unittest import mock

from asgiref.sync import sync_to_async
from asgiref.testing import ApplicationCommunicator
from django.contrib.auth.models import Group, Permission
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TransactionTestCase, override_settings

from accounts.models import User
from config.asgi import application
from rules.services.compiler import check_ruleset
from rules.tests.helpers import make_ruleset
from scans import consumers, services
from scans.models import ScanJob
from scans.tests.helpers import ScanDirMixin, drain, worker

ORIGIN = "http://testserver"


class Socket(ApplicationCommunicator):
    def __init__(self, headers: list[tuple[bytes, bytes]], path: str = "/ws/scans/") -> None:
        super().__init__(
            application,
            {
                "type": "websocket",
                "path": path,
                "raw_path": path.encode(),
                "query_string": b"",
                "headers": headers,
                "scheme": "ws",
                "subprotocols": [],
                "server": ("testserver", 80),
                "client": ("127.0.0.1", 50000),
            },
        )

    async def connect(self) -> tuple[bool, int | None]:
        await self.send_input({"type": "websocket.connect"})
        response = await self.receive_output(5)
        if response["type"] == "websocket.close":
            return False, response.get("code")
        return response["type"] == "websocket.accept", None

    async def send_json(self, data: Any) -> None:
        await self.send_input({"type": "websocket.receive", "text": json.dumps(data)})

    async def send_text(self, text: str) -> None:
        await self.send_input({"type": "websocket.receive", "text": text})

    async def send_bytes(self, data: bytes) -> None:
        await self.send_input({"type": "websocket.receive", "bytes": data})

    async def receive(self, timeout: float = 5) -> dict[str, Any]:
        """The next output: a message as a dict, or {"close": code}."""
        output = await self.receive_output(timeout)
        if output["type"] == "websocket.close":
            return {"close": output.get("code", 1000)}
        return json.loads(output["text"])

    async def receive_type(self, kind: str, timeout: float = 5) -> dict[str, Any]:
        while True:
            message = await self.receive(timeout)
            if message.get("type") == kind or "close" in message:
                return message

    async def close(self) -> None:
        await self.send_input({"type": "websocket.disconnect", "code": 1000})
        await self.wait(1)


@override_settings(ALLOWED_HOSTS=["testserver"], YARADUDE_SCAN_INLINE_MAX_BYTES=0)
class ConsumerTests(ScanDirMixin, TransactionTestCase):
    cache = False

    def setUp(self) -> None:
        super().setUp()
        from accounts.roles import ensure_roles

        ensure_roles()
        self.viewer = self.make_user("viewer", "Viewers")
        self.editor = self.make_user("editor", "Editors")
        self.outsider = self.make_user("outsider", None)
        ruleset = make_ruleset('rule hello { strings: $h = "hello" condition: $h }\n', name="r")
        check_ruleset(ruleset)
        consumers._open_sockets.clear()

    def make_user(self, name: str, group: str | None) -> User:
        user = User.objects.create_user(username=name, password="x")
        if group:
            user.groups.add(Group.objects.get(name=group))
        return user

    def cookie(self, user: User) -> bytes:
        client = Client()
        client.force_login(user)
        return f"sessionid={client.cookies['sessionid'].value}".encode()

    def headers(
        self, user: User | None, origin: str | None = ORIGIN, host: str = "testserver"
    ) -> list[tuple[bytes, bytes]]:
        headers = [(b"host", host.encode())]
        if origin is not None:
            headers.append((b"origin", origin.encode()))
        if user is not None:
            headers.append((b"cookie", self.cookie(user)))
        return headers

    def submit(self, user: User, count: int = 1) -> list[ScanJob]:
        files = [SimpleUploadedFile(f"s{i}.bin", b"say hello") for i in range(count)]
        return services.submit_samples(files, user)

    async def opened(self, user: User) -> Socket:
        socket = Socket(await sync_to_async(self.headers)(user))
        accepted, code = await socket.connect()
        self.assertTrue(accepted, code)
        hello = await socket.receive()
        self.assertEqual(hello["type"], "hello")
        return socket

    # -- admission -----------------------------------------------------------

    async def test_anonymous_is_refused(self) -> None:
        socket = Socket(self.headers(None))
        self.assertEqual(await socket.connect(), (False, consumers.CLOSE_FORBIDDEN))

    async def test_user_without_scan_permission_is_refused(self) -> None:
        socket = Socket(await sync_to_async(self.headers)(self.outsider))
        self.assertEqual(await socket.connect(), (False, consumers.CLOSE_FORBIDDEN))

    async def test_inactive_user_is_refused(self) -> None:
        headers = await sync_to_async(self.headers)(self.viewer)
        await User.objects.filter(pk=self.viewer.pk).aupdate(is_active=False)
        self.assertEqual(await Socket(headers).connect(), (False, consumers.CLOSE_FORBIDDEN))

    async def test_origin_must_be_this_site(self) -> None:
        for origin in (
            None,
            "http://evil.example",
            "https://testserver",
            "null",
            "http://testserver.evil.example",
        ):
            with self.subTest(origin=origin):
                headers = await sync_to_async(self.headers)(self.viewer, origin)
                self.assertEqual(
                    await Socket(headers).connect(), (False, consumers.CLOSE_FORBIDDEN)
                )
        # A Host outside ALLOWED_HOSTS is refused even when Origin matches it.
        headers = await sync_to_async(self.headers)(
            self.viewer, "http://evil.example", "evil.example"
        )
        self.assertEqual(await Socket(headers).connect(), (False, consumers.CLOSE_FORBIDDEN))

    @override_settings(CSRF_TRUSTED_ORIGINS=["https://scan.example"])
    async def test_trusted_origin_and_proxied_https(self) -> None:
        headers = await sync_to_async(self.headers)(self.viewer, "https://scan.example")
        self.assertTrue((await Socket(headers).connect())[0])
        headers = await sync_to_async(self.headers)(self.viewer, "https://testserver")
        headers.append((b"x-forwarded-proto", b"https"))
        with override_settings(SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO", "https")):
            self.assertTrue((await Socket(headers).connect())[0])

    async def test_sockets_per_user_are_limited(self) -> None:
        sockets = [await self.opened(self.viewer) for _ in range(consumers.MAX_SOCKETS_PER_USER)]
        extra = Socket(await sync_to_async(self.headers)(self.viewer))
        self.assertEqual((await extra.connect())[0], True)
        self.assertEqual(await extra.receive(), {"close": consumers.CLOSE_RATE})
        await sockets[0].close()
        again = await self.opened(self.viewer)
        await again.close()
        for socket in sockets[1:]:
            await socket.close()

    # -- protocol happy path ---------------------------------------------------

    async def test_subscribe_and_follow_a_job_to_the_end(self) -> None:
        socket = await self.opened(self.viewer)
        (job,) = await sync_to_async(self.submit)(self.editor)
        await socket.send_json({"v": 1, "type": "subscribe", "jobs": [str(job.pk), "nope"]})
        first = await socket.receive()
        self.assertEqual(first["type"], "job")
        self.assertEqual(first["job"]["id"], str(job.pk))
        self.assertEqual(
            (first["job"]["state"], first["job"]["submitted_by"]), ("queued", "editor")
        )
        self.assertIsNone(first["job"]["result"])
        self.assertEqual(await socket.receive(), {"v": 1, "type": "job_unknown", "id": "nope"})

        await sync_to_async(lambda: drain(worker()))()
        final = await socket.receive_type("job")
        self.assertEqual(final["job"]["state"], "finished")
        self.assertEqual([m["rule"] for m in final["job"]["result"]["matches"]], ["hello"])
        await socket.send_json({"v": 1, "type": "ping", "id": "p1"})
        self.assertEqual(await socket.receive_type("pong"), {"v": 1, "type": "pong", "id": "p1"})
        await socket.close()

    async def test_follow_new_jobs(self) -> None:
        socket = await self.opened(self.viewer)
        await socket.send_json({"v": 1, "type": "follow", "scope": "mine"})
        await socket.send_json({"v": 1, "type": "ping", "id": "sync"})
        await socket.receive_type("pong")
        (other,) = await sync_to_async(self.submit)(self.editor)
        (mine,) = await sync_to_async(self.submit)(self.viewer)
        message = await socket.receive_type("job")
        self.assertEqual(message["job"]["id"], str(mine.pk))
        await socket.send_json({"v": 1, "type": "follow", "scope": "all"})
        await socket.send_json({"v": 1, "type": "ping", "id": "sync"})
        await socket.receive_type("pong")
        (third,) = await sync_to_async(self.submit)(self.editor)
        message = await socket.receive_type("job")
        self.assertEqual(message["job"]["id"], str(third.pk))
        self.assertNotEqual(message["job"]["id"], str(other.pk))
        await socket.close()

    async def test_compiled_status_in_hello(self) -> None:
        socket = Socket(await sync_to_async(self.headers)(self.viewer))
        await socket.connect()
        hello = await socket.receive()
        self.assertEqual(hello["limits"]["max_message_bytes"], consumers.MAX_MESSAGE_BYTES)
        self.assertEqual(hello["user"], "viewer")
        self.assertIn("pending", hello["compiled"])
        await socket.close()

    # -- garbage and limits ------------------------------------------------------

    async def expect_error_and_close(self, socket: Socket, code: str, close: int) -> None:
        error = await socket.receive()
        self.assertEqual((error["type"], error["code"]), ("error", code))
        self.assertEqual(await socket.receive(), {"close": close})

    async def test_garbage_closes_cleanly(self) -> None:
        cases: list[tuple[Any, str]] = [
            ("not json", "bad_message"),
            ("[1, 2]", "bad_message"),
            (json.dumps({"type": "ping"}), "unsupported_version"),
            (json.dumps({"v": 2, "type": "ping"}), "unsupported_version"),
            (json.dumps({"v": 1, "type": "launch"}), "unknown_type"),
            (json.dumps({"v": 1, "type": "subscribe", "jobs": "x"}), "bad_message"),
            (json.dumps({"v": 1, "type": "subscribe", "jobs": [1]}), "bad_message"),
            (json.dumps({"v": 1, "type": "follow", "scope": "everything"}), "bad_message"),
            (json.dumps({"v": 1, "type": "ping", "id": "x" * 100}), "bad_message"),
        ]
        for text, code in cases:
            with self.subTest(text=text):
                socket = await self.opened(self.viewer)
                await socket.send_text(text)
                await self.expect_error_and_close(socket, code, consumers.CLOSE_PROTOCOL)

    async def test_binary_frames_are_refused(self) -> None:
        socket = await self.opened(self.viewer)
        await socket.send_bytes(b"MZ\x90\x00")
        await self.expect_error_and_close(socket, "binary_not_accepted", consumers.CLOSE_PROTOCOL)

    async def test_message_size_limit(self) -> None:
        socket = await self.opened(self.viewer)
        await socket.send_json({"v": 1, "type": "ping", "id": "x", "pad": "y" * 5000})
        await self.expect_error_and_close(socket, "too_large", consumers.CLOSE_TOO_LARGE)

    async def test_message_rate_limit(self) -> None:
        socket = await self.opened(self.viewer)
        for number in range(consumers.RATE_MESSAGES):
            await socket.send_json({"v": 1, "type": "ping", "id": str(number)})
            await socket.receive_type("pong")
        await socket.send_json({"v": 1, "type": "ping", "id": "one too many"})
        await self.expect_error_and_close(socket, "rate_limited", consumers.CLOSE_RATE)

    async def test_too_many_jobs_is_not_fatal(self) -> None:
        jobs = await sync_to_async(self.submit)(self.viewer, 3)
        socket = await self.opened(self.viewer)
        with mock.patch.object(consumers, "MAX_JOBS", 2):
            await socket.send_json({"v": 1, "type": "subscribe", "jobs": [str(j.pk) for j in jobs]})
            await socket.receive_type("job")
            await socket.receive_type("job")
            error = await socket.receive()
        self.assertEqual(error["code"], "too_many_jobs")
        await socket.send_json({"v": 1, "type": "ping", "id": "still open"})
        self.assertEqual((await socket.receive_type("pong"))["id"], "still open")
        await socket.close()

    # -- access to jobs ----------------------------------------------------------

    async def test_permission_removed_while_connected(self) -> None:
        socket = await self.opened(self.viewer)
        await sync_to_async(self.viewer.groups.clear)()
        with mock.patch.object(consumers, "RECHECK_SECONDS", 0):
            message = await socket.receive_type("close")
        self.assertEqual(message, {"close": consumers.CLOSE_FORBIDDEN})

    async def test_connection_lifetime(self) -> None:
        socket = await self.opened(self.viewer)
        with mock.patch.object(consumers, "LIFETIME_SECONDS", 0):
            self.assertEqual(
                await socket.receive_type("close"), {"close": consumers.CLOSE_LIFETIME}
            )

    async def test_scan_permission_alone_is_enough(self) -> None:
        user = await sync_to_async(self.make_user)("scanner", None)
        permission = await Permission.objects.aget(codename="scan_rules")
        await sync_to_async(user.user_permissions.add)(permission)
        socket = await self.opened(user)
        await socket.close()
