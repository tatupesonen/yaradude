"""JSON responses and errors of the API."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from django import forms
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.http import content_disposition_header  # ty: ignore[missing-module-member]  # Django 4.2 API absent from django-types 0.24

from accounts.models import User
from api.models import ApiKey
from rules.services.exporter import ExportFile

REALM = "yaradude API"


class ApiError(Exception):
    """An error answered as `{"error": {"code", "message", ...}}` with `status`."""

    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        fields: dict[str, list[str]] | None = None,
        extra: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.fields = fields
        self.extra = extra or {}
        self.headers = headers or {}

    def response(self) -> JsonResponse:
        body: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.fields is not None:
            body["fields"] = self.fields
        body.update(self.extra)
        return json_response({"error": body}, status=self.status, headers=self.headers)


def json_response(
    data: Any, status: int = 200, headers: dict[str, str] | None = None
) -> JsonResponse:
    response = JsonResponse(data, status=status, safe=False, headers=headers)
    # Every API response is specific to the key's user.
    response["Cache-Control"] = "no-store"
    return response


def no_content() -> HttpResponse:
    response = HttpResponse(status=204)
    response["Cache-Control"] = "no-store"
    return response


def file_response(export: ExportFile) -> HttpResponse:
    response = HttpResponse(
        export.content,
        content_type=export.content_type,
        headers={"Content-Disposition": content_disposition_header(True, export.filename)},
    )
    response["Cache-Control"] = "no-store"
    return response


def unauthorized(code: str, message: str) -> ApiError:
    error = "invalid_request" if code == "missing_key" else "invalid_token"
    return ApiError(
        401,
        code,
        message,
        headers={"WWW-Authenticate": f'Bearer realm="{REALM}", error="{error}"'},
    )


def form_error(form: forms.Form) -> ApiError:
    """400 with the form's messages per field (`__all__` for form-wide errors)."""
    fields = {
        name: [str(message) for message in messages] for name, messages in form.errors.items()
    }
    return ApiError(400, "invalid", "The request is not valid.", fields=fields)


@dataclass
class Call:
    """One authenticated API request: the request, the key's user and the key."""

    request: HttpRequest
    user: User
    key: ApiKey
    _json: dict[str, Any] | None = field(default=None, repr=False)

    def absolute(self, path: str) -> str:
        return self.request.build_absolute_uri(path)

    def json(self) -> dict[str, Any]:
        """The JSON object in the request body (400/415 when it is not one)."""
        if self._json is None:
            if self.request.content_type != "application/json":
                raise ApiError(415, "unsupported_media_type", "Send the body as application/json.")
            try:
                data = json.loads(self.request.body or b"null")
            except ValueError:  # includes UnicodeDecodeError
                raise ApiError(400, "invalid_json", "The body is not valid JSON.") from None
            if not isinstance(data, dict):
                raise ApiError(400, "invalid_json", "The body must be a JSON object.")
            self._json = data
        return self._json
