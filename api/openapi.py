"""The OpenAPI 3.1 description, generated from api.registry and api.schemas."""

from __future__ import annotations

from typing import Any

from django.http import HttpRequest

from api import schemas
from api.registry import ENDPOINTS, GROUPS, PREFIX, Body, Endpoint, Param

PATH_SCHEMAS: dict[str, dict[str, Any]] = {
    "int": {"type": "integer"},
    "uuid": {"type": "string", "format": "uuid"},
    "str": {"type": "string"},
}
ERROR_HEADERS = {
    401: {"WWW-Authenticate": {"schema": {"type": "string"}, "description": "Bearer challenge."}},
    429: {"Retry-After": {"schema": {"type": "integer"}, "description": "Seconds to wait."}},
}


def base_url(request: HttpRequest) -> str:
    """The API's base URL as the client reached the server (scheme and host included)."""
    return request.build_absolute_uri(PREFIX)


def _kind(kind: str) -> dict[str, Any]:
    if kind == "file":
        return {"type": "string", "contentMediaType": "application/octet-stream"}
    return {"type": kind}


def _param(param: Param) -> dict[str, Any]:
    schema: dict[str, Any] = _kind(param.type)
    if param.enum:
        schema["enum"] = list(param.enum)
    if param.repeated:
        schema = {"type": "array", "items": schema}
    result: dict[str, Any] = {
        "name": param.name,
        "in": "query",
        "required": False,
        "description": param.description,
        "schema": schema,
    }
    if param.repeated:
        result.update(style="form", explode=True)
    return result


def _body(body: Body) -> dict[str, Any]:
    properties: dict[str, Any] = {}
    for field in body.fields:
        schema: dict[str, Any] = _kind(field.type)
        if field.repeated:
            schema = {"type": "array", "items": schema}
        properties[field.name] = {**schema, "description": field.description}
    content_type = "application/json" if body.kind == "json" else "multipart/form-data"
    return {
        "required": any(field.required for field in body.fields),
        "content": {
            content_type: {
                "schema": {
                    "type": "object",
                    "properties": properties,
                    "required": [field.name for field in body.fields if field.required],
                }
            }
        },
    }


def operation(e: Endpoint) -> dict[str, Any]:
    permissions = ", ".join(f"`{p}`" for p in e.permissions) or "any valid key"
    responses: dict[str, Any] = {}
    for reply in e.replies:
        response: dict[str, Any] = {"description": reply.description}
        if reply.schema:
            response["content"] = {"application/json": {"schema": schemas.ref(reply.schema)}}
        elif reply.file:
            response["content"] = {reply.file: {"schema": {"type": "string", "format": "binary"}}}
            response["headers"] = {
                "Content-Disposition": {
                    "schema": {"type": "string"},
                    "description": "`attachment` with the file name.",
                }
            }
        if reply.status in ERROR_HEADERS:
            response["headers"] = ERROR_HEADERS[reply.status]
        responses[str(reply.status)] = response
    result: dict[str, Any] = {
        "operationId": e.operation,
        "tags": [e.group],
        "summary": e.summary,
        "description": f"{e.description}\n\nPermission: {permissions}.".strip(),
        "x-permissions": list(e.permissions),
        "parameters": [
            {"name": name, "in": "path", "required": True, "schema": PATH_SCHEMAS[converter]}
            for name, converter in e.path_param_types
        ]
        + [_param(param) for param in e.params],
        "responses": responses,
    }
    if e.body:
        result["requestBody"] = _body(e.body)
    return result


def openapi_document(request: HttpRequest) -> dict[str, Any]:
    paths: dict[str, dict[str, Any]] = {}
    for e in ENDPOINTS:
        paths.setdefault(e.path, {})[e.method.lower()] = operation(e)
    return {
        "openapi": "3.1.0",
        "info": {
            "title": "yaradude API",
            "version": "1",
            "description": "Manage YARA rules with YARA-X. Authenticate with a personal API "
            "key: `Authorization: Bearer <key>`. Errors are JSON objects "
            '`{"error": {"code": …, "message": …}}`.',
        },
        "servers": [{"url": base_url(request)}],
        "security": [{"apiKey": []}],
        "tags": [{"name": group} for group in GROUPS],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "apiKey": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "A personal API key (`yd_…`) from the API keys page.",
                }
            },
            "schemas": schemas.COMPONENTS,
        },
    }
