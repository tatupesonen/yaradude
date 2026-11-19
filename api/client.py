"""
yaradude_client: a minimal client for the yaradude API, standard library only
(Python 3.9 or newer, no third-party packages).

Save it as yaradude_client.py next to your script, then:

    export YARADUDE_API_KEY=yd_...          # from the API keys page
    python3 -c 'from yaradude_client import call; print(call("GET", "/me/"))'

YARADUDE_URL overrides the server address below. If the server uses a
certificate from a private CA (for example Caddy's internal CA), point
SSL_CERT_FILE at that CA certificate; verification is never switched off.

call() returns the decoded JSON, None for an empty answer, or, with
save_to, the path of the downloaded file. Errors raise ApiError with the
HTTP status and the API's error object.
"""

from __future__ import annotations

import json
import mimetypes
import os
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

DEFAULT_URL = "http://localhost:8000"
BASE_URL = os.environ.get("YARADUDE_URL", DEFAULT_URL).rstrip("/") + "/api/v1"


class ApiError(Exception):
    def __init__(self, status: int, error: dict) -> None:
        super().__init__(f"HTTP {status}: {error.get('code')}: {error.get('message')}")
        self.status = status
        self.error = error


def _multipart(fields: dict, files: dict) -> tuple[bytes, str]:
    boundary = uuid.uuid4().hex
    parts = []
    for name, value in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'
            f"{value}\r\n".encode()
        )
    for name, paths in files.items():
        for path in [paths] if isinstance(paths, (str, Path)) else paths:
            path = Path(path)
            filename = path.name.replace('"', "_")
            kind = mimetypes.guess_type(filename)[0] or "application/octet-stream"
            parts.append(
                f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; '
                f'filename="{filename}"\r\nContent-Type: {kind}\r\n\r\n'.encode()
                + path.read_bytes()
                + b"\r\n"
            )
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def call(method, path, *, query=None, body=None, fields=None, files=None, save_to=None):
    """
    method: "GET", "POST", "PUT" or "DELETE"; path: e.g. "/rules/42/".
    query: dict of query parameters (lists repeat the parameter).
    body: a dict sent as JSON. fields/files: multipart form fields and
    {field: path or [paths]} uploads. save_to: directory for a download.
    """
    key = os.environ.get("YARADUDE_API_KEY")
    if not key:
        raise SystemExit("Set YARADUDE_API_KEY to your API key (create one on the API keys page).")
    url = BASE_URL + path
    if query:
        url += "?" + urllib.parse.urlencode(query, doseq=True)
    headers = {"Authorization": f"Bearer {key}", "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        headers["Content-Type"] = "application/json"
    elif fields or files:
        data, headers["Content-Type"] = _multipart(fields or {}, files or {})
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request) as response:
            content = response.read()
            if save_to is not None:
                name = Path(response.headers.get_filename() or "download").name
                target = Path(save_to) / name
                target.write_bytes(content)
                return target
            if response.headers.get_content_type() == "application/json":
                return json.loads(content)
            return content or None
    except urllib.error.HTTPError as error:
        try:
            detail = json.loads(error.read())["error"]
        except (ValueError, KeyError, TypeError):
            detail = {"code": "http_error", "message": error.reason}
        raise ApiError(error.code, detail) from None
