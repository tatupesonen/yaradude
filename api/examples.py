"""
curl and Python examples for every endpoint, generated from the endpoint
declarations, so they always name a real route with its method. The key is
never part of an example: they read it from the environment variable
YARADUDE_API_KEY.
"""

from __future__ import annotations

import json
import pprint
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from django.urls import reverse

from api import schemas
from api.registry import PATH_EXAMPLES, Endpoint

KEY_VARIABLE = "YARADUDE_API_KEY"
CLIENT_SOURCE = Path(__file__).with_name("client.py")
SECOND_FILE = {"first.yar": "second.yar"}


@dataclass(frozen=True)
class Example:
    curl: str
    python: str
    response_status: int
    response: str  # pretty JSON, or a description of a file / empty answer


def path_of(e: Endpoint) -> str:
    """The example path below /api/v1, e.g. `/rules/42/`."""
    kwargs = {name: PATH_EXAMPLES[name] for name in e.path_params}
    full = reverse(f"api:{e.operation}", kwargs=kwargs)
    return full.removeprefix("/api/v1")


def query_of(e: Endpoint) -> dict[str, Any]:
    return {p.name: p.example for p in e.params if p.example is not None}


def body_of(e: Endpoint) -> dict[str, Any]:
    if e.body is None:
        return {}
    return {f.name: f.example for f in e.body.fields if f.example is not None}


def files_of(e: Endpoint) -> dict[str, list[str]]:
    """Example upload file names per multipart file field."""
    if e.body is None or e.body.kind != "multipart":
        return {}
    files = {}
    for f in e.body.fields:
        if f.type == "file" and isinstance(f.example, str):
            names = [f.example]
            if f.repeated and f.example in SECOND_FILE:
                names.append(SECOND_FILE[f.example])
            files[f.name] = names
    return files


def form_fields_of(e: Endpoint) -> dict[str, Any]:
    if e.body is None or e.body.kind != "multipart":
        return {}
    return {f.name: f.example for f in e.body.fields if f.type != "file" and f.example is not None}


def url_of(e: Endpoint, base_url: str) -> str:
    from urllib.parse import urlencode

    url = base_url + path_of(e)
    query = query_of(e)
    return f"{url}?{urlencode(query)}" if query else url


def curl(e: Endpoint, base_url: str) -> str:
    lines = ["curl -sS"]
    if e.method != "GET":
        lines[0] += f" -X {e.method}"
    if e.is_download:
        lines[0] += " -OJ"
    lines.append(f'-H "Authorization: Bearer ${KEY_VARIABLE}"')
    if e.body is not None and e.body.kind == "json":
        body = body_of(e)
        if body:
            lines.append("-H 'Content-Type: application/json'")
            lines.append("-d " + shlex.quote(json.dumps(body)))
    for name, value in form_fields_of(e).items():
        lines.append("-F " + shlex.quote(f"{name}={value}"))
    for name, filenames in files_of(e).items():
        lines.extend("-F " + shlex.quote(f"{name}=@{filename}") for filename in filenames)
    lines.append(shlex.quote(url_of(e, base_url)))
    return " \\\n  ".join(lines)


def _literal(value: Any) -> str:
    return pprint.pformat(value, width=80, sort_dicts=False)


def python(e: Endpoint) -> str:
    args = [repr(e.method), repr(path_of(e))]
    if query := query_of(e):
        args.append(f"query={_literal(query)}")
    if e.body is not None and e.body.kind == "json" and (body := body_of(e)):
        args.append(f"body={_literal(body)}")
    if fields := form_fields_of(e):
        args.append(f"fields={_literal(fields)}")
    if files := files_of(e):
        args.append(f"files={_literal(files)}")
    if e.is_download:
        args.append('save_to="."')
    call = f"call({', '.join(args)})"
    if len(call) > 88:
        call = "call(\n    " + ",\n    ".join(args) + ",\n)"
    lines = ["from yaradude_client import call", ""]
    if e.is_download:
        lines += [f"path = {call}", 'print("saved", path)']
    elif any(reply.status == 204 for reply in e.replies):
        lines += [call]
    else:
        lines += [f"result = {call}", "print(result)"]
    return "\n".join(lines)


def response(e: Endpoint) -> tuple[int, str]:
    reply = next(r for r in e.replies if 200 <= r.status < 300)
    if reply.schema:
        value = schemas.example(schemas.ref(reply.schema))
        return reply.status, json.dumps(value, indent=2, ensure_ascii=False)
    if reply.file:
        return reply.status, f"(file download: {reply.file}, saved under the name in "
        "Content-Disposition)"
    return reply.status, "(no content)"


def example(e: Endpoint, base_url: str) -> Example:
    status, body = response(e)
    return Example(curl=curl(e, base_url), python=python(e), response_status=status, response=body)


def client_source(server_url: str) -> str:
    """The client module with the server's address as its default."""
    source = CLIENT_SOURCE.read_text()
    default = 'DEFAULT_URL = "http://localhost:8000"'
    if default not in source:
        raise RuntimeError("api/client.py no longer defines DEFAULT_URL as expected")
    return source.replace(default, f"DEFAULT_URL = {server_url.rstrip('/')!r}")
