import base64
import logging
import os
import stat
import time
from datetime import timedelta
from typing import Any
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import TestCase, override_settings
from django.utils import timezone
from django_tasks_db.models import DBTaskResult

from rules.services import scanner
from rules.services.compiler import check_ruleset
from rules.tests.helpers import make_ruleset
from scans import maintenance, services, spool
from scans.models import ScanJob, WorkerProcess
from scans.tasking import TaskResultStatus
from scans.tests.helpers import ScanDirMixin, drain, make_user, worker

MARKER = b"UNIQUE-SAMPLE-MARKER-7f3a9c"
SAMPLE = b"MZ" + b"\x00" * 30 + b"hello world " + MARKER + b" \x01\x02\x03"


def upload(content: bytes = SAMPLE, name: str = "sample.bin") -> SimpleUploadedFile:
    return SimpleUploadedFile(name, content)


def spool_files() -> list[str]:
    return sorted(os.listdir(spool.spool_dir()))


class JobTestCase(ScanDirMixin, TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.user = make_user("alice")
        ruleset = make_ruleset(
            'rule hello : greet { strings: $h = "hello" condition: $h }\n'
            'rule world { strings: $w = "world" condition: $w }\n'
            "rule slow { condition: for all i in (0..filesize) : "
            "( for all j in (0..filesize) : ( uint8(i) != uint8(j) or i >= 0 ) ) }\n",
            name="demo/set.yar",
        )
        check_ruleset(ruleset)
        self.ruleset = ruleset


class FastPathTests(JobTestCase):
    def test_small_single_sample_is_scanned_at_once(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        self.assertEqual((job.state, job.phase, job.inline), ("finished", "done", True))
        job.refresh_from_db()
        assert job.result is not None
        self.assertEqual(
            sorted(m["rule"] for m in job.result["matches"]), ["hello", "slow", "world"]
        )
        self.assertEqual(job.match_count, 3)
        self.assertEqual((job.sample_name, job.sample_size), ("sample.bin", len(SAMPLE)))
        self.assertIsNotNone(job.started_at)
        self.assertEqual(job.user, self.user)
        self.assertEqual(DBTaskResult.objects.count(), 0)  # never queued
        self.assertEqual(spool_files(), [])

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_threshold_zero_always_queues(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        self.assertEqual((job.state, job.inline), ("queued", False))

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=10)
    def test_larger_than_threshold_is_queued(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        self.assertEqual(job.state, "queued")
        (small,) = services.submit_samples([upload(b"hello")], self.user)
        self.assertEqual((small.state, small.inline), ("finished", True))

    def test_several_samples_are_queued_as_one_batch(self) -> None:
        jobs = services.submit_samples([upload(), upload(b"world", "b.txt")], self.user)
        self.assertEqual([j.state for j in jobs], ["queued", "queued"])
        self.assertIsNotNone(jobs[0].batch)
        self.assertEqual(jobs[0].batch, jobs[1].batch)
        self.assertEqual(len(spool_files()), 2)

    def test_busy_fast_path_sends_the_sample_to_the_queue(self) -> None:
        with services._inline_lane:
            (job,) = services.submit_samples([upload()], self.user)
        self.assertEqual(job.state, "queued")

    def test_fast_path_timeout_hands_over_to_a_worker(self) -> None:
        with mock.patch.object(
            scanner, "scan_bytes", side_effect=scanner.ScanTimeout("stopped")
        ) as scan:
            (job,) = services.submit_samples([upload()], self.user)
        self.assertEqual(scan.call_args.kwargs["timeout"], 1)
        self.assertEqual((job.state, job.inline), ("queued", False))
        drain(worker())
        job.refresh_from_db()
        self.assertEqual(job.state, "finished")

    def test_limits_are_applied(self) -> None:
        (job,) = services.submit_samples([upload()], self.user, tag="greet")
        assert job.result is not None
        self.assertEqual([m["rule"] for m in job.result["matches"]], ["hello"])
        (job,) = services.submit_samples([upload()], self.user, path="other/")
        assert job.result is not None
        self.assertEqual(job.result["matches"], [])
        self.assertEqual(job.options, {"path": "other/", "tag": "", "rulesets": None})

    def test_submission_limits(self) -> None:
        with self.assertRaises(scanner.ScanError):
            services.submit_samples([], self.user)
        with override_settings(YARADUDE_SCAN_MAX_SAMPLES=2), self.assertRaises(scanner.ScanError):
            services.submit_samples([upload()] * 3, self.user)


class LifecycleTests(JobTestCase):
    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_queued_running_finished(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        self.assertEqual((job.state, job.phase), ("queued", "queued"))
        self.assertEqual(len(spool_files()), 1)
        seen: list[tuple[str, str]] = []
        real_scan = scanner.scan_bytes

        def watch(*args: Any, **kwargs: Any) -> scanner.ScanResult:
            current = ScanJob.objects.get(pk=job.pk)
            seen.append((current.state, current.phase))
            return real_scan(*args, **kwargs)

        scan_worker = worker()
        with mock.patch.object(scanner, "scan_bytes", side_effect=watch):
            self.assertEqual(drain(scan_worker), 1)
        self.assertEqual(seen, [("running", "scanning")])
        job.refresh_from_db()
        self.assertEqual((job.state, job.phase, job.error), ("finished", "done", ""))
        self.assertEqual(job.worker_id, scan_worker.worker_id)
        self.assertEqual(job.match_count, 3)
        self.assertIsNotNone(job.finished_at)
        self.assertEqual(job.spool_token, "")
        self.assertEqual(spool_files(), [])
        task = DBTaskResult.objects.get(id=job.task_id)
        self.assertEqual(task.status, TaskResultStatus.SUCCESSFUL)

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0, YARADUDE_SCAN_TIMEOUT=1)
    def test_timeout_fails_the_job_and_removes_the_sample(self) -> None:
        (job,) = services.submit_samples([upload(b"a" * 200_000)], self.user)
        drain(worker())
        job.refresh_from_db()
        self.assertEqual(job.state, "failed")
        self.assertIn("stopped after 1 seconds", job.error)
        self.assertEqual(spool_files(), [])

    def test_oversize_sample_is_a_failed_job_and_never_spooled(self) -> None:
        with override_settings(YARADUDE_SCAN_MAX_BYTES=10):
            jobs = services.submit_samples([upload(), upload(b"tiny")], self.user)
        self.assertEqual([j.state for j in jobs], ["failed", "queued"])
        self.assertIn("larger than the limit", jobs[0].error)
        self.assertEqual(jobs[0].sample_sha256, "")
        self.assertEqual(len(spool_files()), 1)

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_unexpected_error_fails_the_job_and_removes_the_sample(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        with (
            mock.patch.object(scanner, "scan_bytes", side_effect=RuntimeError("boom")),
            self.assertLogs("scans.services", "ERROR"),
        ):
            drain(worker())
        job.refresh_from_db()
        self.assertEqual(
            (job.state, job.error), ("failed", "The scan failed because of an internal error.")
        )
        self.assertEqual(spool_files(), [])

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_missing_or_damaged_spool_file(self) -> None:
        first, second = services.submit_samples([upload(), upload(b"other")], self.user)
        spool.delete(first.spool_token)
        path = spool.spool_dir() / second.spool_token
        path.write_bytes(b"tampered")
        drain(worker())
        first.refresh_from_db()
        second.refresh_from_db()
        self.assertEqual(first.state, "failed")
        self.assertIn("no longer available", first.error)
        self.assertIn("damaged", second.error)
        self.assertEqual(spool_files(), [])

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_job_already_failed_is_not_scanned(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        ScanJob.objects.filter(pk=job.pk).update(state=ScanJob.State.FAILED)
        with mock.patch.object(scanner, "scan_bytes") as scan:
            drain(worker())
        scan.assert_not_called()
        self.assertEqual(spool_files(), [])


class SpoolTests(JobTestCase):
    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_spool_is_private_and_unpredictable(self) -> None:
        jobs = services.submit_samples([upload(), upload()], self.user)
        directory = spool.spool_dir()
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        names = spool_files()
        self.assertEqual(len(set(names)), 2)
        for name in names:
            self.assertEqual(stat.S_IMODE((directory / name).stat().st_mode), 0o600)
            self.assertGreaterEqual(len(name), 43)  # 256 random bits
            self.assertNotIn(str(jobs[0].pk), name)
        self.assertEqual({j.spool_token for j in jobs}, set(names))

    def test_tokens_cannot_escape_the_spool(self) -> None:
        for token in ("../x", "a/b", "", "."):
            with self.subTest(token=token), self.assertRaises(ValueError):
                spool.read(token)

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_crashed_worker_is_repaired(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        # A worker claimed the job and died mid-scan.
        WorkerProcess.objects.create(
            worker_id="dead", role="scan", last_seen=timezone.now() - timedelta(hours=1)
        )
        ScanJob.objects.filter(pk=job.pk).update(state="running", worker_id="dead")
        DBTaskResult.objects.filter(id=job.task_id).update(
            status=TaskResultStatus.RUNNING, worker_ids=["dead"]
        )
        repair = maintenance.repair()
        self.assertEqual(repair.lost_running, 1)
        job.refresh_from_db()
        self.assertEqual(job.state, "failed")
        self.assertEqual(job.error, maintenance.WORKER_LOST)
        self.assertEqual(spool_files(), [])
        self.assertEqual(DBTaskResult.objects.get(id=job.task_id).status, TaskResultStatus.FAILED)

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_supervisor_reports_a_dead_worker_at_once(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        WorkerProcess.objects.create(worker_id="w1", role="scan")  # heartbeat still fresh
        ScanJob.objects.filter(pk=job.pk).update(state="running", worker_id="w1")
        self.assertEqual(maintenance.repair().lost_running, 0)
        self.assertEqual(maintenance.forget_worker("w1").lost_running, 1)

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_job_lost_from_the_queue_is_failed(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        DBTaskResult.objects.all().delete()
        self.assertEqual(maintenance.repair().lost_queued, 1)
        job.refresh_from_db()
        self.assertEqual((job.state, job.error), ("failed", maintenance.QUEUE_LOST))
        self.assertEqual(spool_files(), [])

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_orphaned_spool_files_are_swept_after_a_grace_period(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        orphan = spool.write(b"left behind by a crashed submitter")
        fresh = spool.write(b"being submitted right now")
        old = time.time() - spool.SWEEP_GRACE_SECONDS - 10
        os.utime(spool.spool_dir() / orphan, (old, old))
        os.utime(spool.spool_dir() / job.spool_token, (old, old))
        self.assertEqual(maintenance.repair().spool_removed, 1)
        self.assertEqual(spool_files(), sorted([job.spool_token, fresh]))

    @override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0)
    def test_failed_enqueue_removes_the_spool_file(self) -> None:
        with (
            mock.patch(
                "django_tasks_db.backend.DatabaseBackend.enqueue", side_effect=RuntimeError("db")
            ),
            self.assertRaises(RuntimeError),
        ):
            services.submit_samples([upload()], self.user)
        self.assertEqual(spool_files(), [])
        self.assertEqual(ScanJob.objects.count(), 0)


class NoSampleBytesTests(JobTestCase):
    def assert_marker_absent(self, text: str) -> None:
        for form in (
            MARKER.decode(),
            MARKER.hex(),
            MARKER.hex(" "),
            base64.b64encode(MARKER).decode()[:20],
        ):
            self.assertNotIn(form, text)

    def test_bytes_never_reach_database_arguments_results_or_logs(self) -> None:
        with self.assertLogs(level=logging.DEBUG) as logs:
            logging.getLogger("scans").debug("start")
            # One inline, two queued; one queued job fails.
            services.submit_samples([upload()], self.user)
            jobs = services.submit_samples([upload(), upload(MARKER * 3, "m.bin")], self.user)
            with override_settings(YARADUDE_SCAN_MAX_BYTES=len(MARKER) * 3 - 1):
                drain(worker())
        self.assert_marker_absent("\n".join(logs.output))
        dump = "\n".join(connection.connection.iterdump())
        self.assert_marker_absent(dump)
        self.assertIn("hello", dump)  # the dump does contain the rules
        for job in jobs:
            task = DBTaskResult.objects.get(id=job.task_id)
            self.assertEqual(task.args_kwargs, {"args": [str(job.pk)], "kwargs": {}})
            self.assertNotIn(job.spool_token or "x", str(task.args_kwargs))
        self.assertEqual(spool_files(), [])


class VisibilityTests(JobTestCase):
    def test_jobs_are_shared_with_everyone_who_may_scan(self) -> None:
        bob = make_user("bob", group="Editors")
        outsider = make_user("outsider", group=None)
        (mine,) = services.submit_samples([upload()], self.user)
        (theirs,) = services.submit_samples([upload()], bob)
        self.assertEqual(
            set(services.visible_jobs(self.user).values_list("pk", flat=True)),
            {mine.pk, theirs.pk},
        )
        opened = services.get_job(self.user, str(theirs.pk))
        self.assertEqual(opened.submitted_by, "bob")
        self.assertEqual(services.job_json(opened)["submitted_by"], "bob")
        # Without the permission: nothing, and "not found" rather than "forbidden".
        self.assertEqual(list(services.visible_jobs(outsider)), [])
        with self.assertRaises(ScanJob.DoesNotExist):
            services.get_job(outsider, mine.pk)
        with self.assertRaises(ScanJob.DoesNotExist):
            services.get_job(self.user, "not-a-uuid")
        inactive = make_user("gone", is_active=False)
        self.assertEqual(list(services.visible_jobs(inactive)), [])

    def test_deleted_submitter(self) -> None:
        bob = make_user("bob")
        (job,) = services.submit_samples([upload()], bob)
        bob.delete()
        job.refresh_from_db()
        self.assertEqual(job.submitted_by, "deleted user")

    def test_result_json_has_no_previews(self) -> None:
        (job,) = services.submit_samples([upload()], self.user)
        data = services.job_json(services.get_job(self.user, job.pk))
        hello = next(m for m in data["result"]["matches"] if m["rule"] == "hello")
        self.assertEqual(hello["patterns"][0]["instances"], [{"offset": 32, "length": 5}])
        self.assertEqual(hello["tags"], ["greet"])
        self.assertEqual(data["result"]["compiled"]["pending"], False)


class RetentionTests(JobTestCase):
    def test_old_finished_jobs_and_task_results_are_deleted(self) -> None:
        with override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0):
            old, recent, waiting = services.submit_samples([upload()] * 3, self.user)
        drain(worker())
        long_ago = timezone.now() - timedelta(days=31)
        ScanJob.objects.filter(pk=old.pk).update(finished_at=long_ago)
        DBTaskResult.objects.filter(id=old.task_id).update(finished_at=long_ago)
        ScanJob.objects.filter(pk=waiting.pk).update(
            state="queued", created_at=long_ago, finished_at=None
        )
        done = maintenance.cleanup()
        self.assertEqual((done.jobs, done.task_results), (1, 1))
        self.assertEqual(set(ScanJob.objects.values_list("pk", flat=True)), {recent.pk, waiting.pk})
        with override_settings(YARADUDE_SCAN_RETENTION_DAYS=0):
            self.assertEqual(maintenance.cleanup().jobs, 1)  # only the finished one

    def test_status(self) -> None:
        with override_settings(YARADUDE_SCAN_INLINE_MAX_BYTES=0):
            services.submit_samples([upload()], self.user)
        worker("scan", "scan-a")
        status = services.system_status()
        self.assertEqual((status.queued, status.running), (1, 0))
        self.assertEqual(status.workers, {"scan": 1})
        self.assertIn("scans.tasks.cleanup_scan_jobs", [r.name for r in status.recurring])
