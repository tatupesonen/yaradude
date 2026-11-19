"""
The single source of truth of the API: every endpoint is declared once with
`@endpoint(...)`, and the URL patterns, the request dispatch (authentication,
rate limit, method, permission), the OpenAPI description, the documentation
pages and their curl/Python examples are all generated from these
declarations.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from django.conf import settings
from django.contrib.auth.decorators import login_not_required  # ty: ignore[missing-module-member]  # Django 5.1 API absent from django-types 0.24
from django.core.exceptions import PermissionDenied, RequestDataTooBig, SuspiciousOperation
from django.http import Http404, HttpRequest, HttpResponse, UnreadablePostError
from django.urls import Resolver404, URLPattern, path, resolve
from django.views.decorators.csrf import csrf_exempt

from api import keys, ratelimit
from api.http import ApiError, Call, unauthorized

logger = logging.getLogger(__name__)

PREFIX = "/api/v1"
Handler = Callable[..., HttpResponse]
Kind = Literal["string", "integer", "boolean", "file"]


@dataclass(frozen=True)
class Param:
    """A query parameter."""

    name: str
    description: str
    type: Kind = "string"
    enum: tuple[str, ...] = ()
    repeated: bool = False
    example: str | int | None = None  # used in the generated request examples


@dataclass(frozen=True)
class BodyField:
    """A field of a JSON or multipart request body."""

    name: str
    description: str
    type: Kind = "string"
    required: bool = False
    repeated: bool = False  # a JSON array, or a repeated multipart field
    example: str | int | list[int] | None = None


@dataclass(frozen=True)
class Body:
    kind: Literal["json", "multipart"]
    fields: tuple[BodyField, ...]


@dataclass(frozen=True)
class Reply:
    """A documented response: a JSON schema component, a file, or no body."""

    status: int
    description: str
    schema: str | None = None  # component name in api.schemas
    file: str | None = None  # content type of a file download


@dataclass(frozen=True)
class Endpoint:
    operation: str  # operationId and URL name (api:<operation>)
    method: str
    route: str  # Django route below /api/v1/
    handler: Handler = field(repr=False, compare=False)
    group: str
    summary: str
    description: str
    permissions: tuple[str, ...]
    params: tuple[Param, ...]
    body: Body | None
    replies: tuple[Reply, ...]

    @property
    def path(self) -> str:
        """The OpenAPI path template, e.g. `/rules/{pk}/`."""
        return "/" + re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", self.route)

    @property
    def path_params(self) -> list[str]:
        return [name for name, _ in self.path_param_types]

    @property
    def path_param_types(self) -> list[tuple[str, str]]:
        """(name, converter) of each path parameter, e.g. ("pk", "int")."""
        return [
            (name, converter or "str")
            for converter, name in re.findall(r"<(?:(\w+):)?(\w+)>", self.route)
        ]

    @property
    def anchor(self) -> str:
        return self.operation.replace("_", "-")

    @property
    def is_download(self) -> bool:
        return any(reply.file for reply in self.replies)


# Section order of the documentation, following the UI's navigation.
GROUPS = ["Dashboard", "Rules", "Rulesets", "Import", "Scan", "Account"]
GROUP_INTROS = {
    "Dashboard": "The counts and recent activity shown on the dashboard.",
    "Rules": "Search, read, create, edit, restore, export and delete rules, and list tags.",
    "Rulesets": "One ruleset per imported file or manual collection.",
    "Import": "Import rule files by upload or from the configured rules directory, and read "
    "the import history.",
    "Scan": "Test-scan samples: synchronously with `/scan/`, or as scan jobs under "
    "`/scans/` that everyone with the scan permission can follow.",
    "Account": "Who the key belongs to, and the machine-readable description of this API.",
}

# Example values of path parameters in the generated examples.
PATH_EXAMPLES: dict[str, int | str] = {
    "pk": 42,
    "number": 2,
    "job_id": "0b6f1c9e-5a2d-4c1b-9f3e-7d8a6b5c4e21",
}

ENDPOINTS: list[Endpoint] = []


def endpoint(
    method: str,
    route: str,
    *,
    operation: str,
    group: str,
    summary: str,
    permissions: tuple[str, ...] = (),
    params: tuple[Param, ...] = (),
    body: Body | None = None,
    replies: tuple[Reply, ...],
    description: str = "",
) -> Callable[[Handler], Handler]:
    """Declare the decorated function as the handler of `method route`."""
    if group not in GROUPS:
        raise ValueError(f"Unknown group {group!r}")

    def register(handler: Handler) -> Handler:
        if any(e.operation == operation for e in ENDPOINTS):
            raise ValueError(f"Duplicate operation {operation!r}")
        if any(e.route == route and e.method == method for e in ENDPOINTS):
            raise ValueError(f"Duplicate route {method} {route}")
        ENDPOINTS.append(
            Endpoint(
                operation=operation,
                method=method,
                route=route,
                handler=handler,
                group=group,
                summary=summary,
                description=description or (handler.__doc__ or "").strip(),
                permissions=permissions,
                params=params,
                body=body,
                replies=replies,
            )
        )
        return handler

    return register


def find(method: str, path: str) -> Endpoint | None:
    """The endpoint serving `method path` (a URL path such as /api/v1/rules/42/), if any."""
    try:
        match = resolve(path)
    except Resolver404:
        return None
    route = match.route.removeprefix(PREFIX.strip("/") + "/")
    return next((e for e in ENDPOINTS if e.route == route and e.method == method), None)


def by_group() -> list[tuple[str, list[Endpoint]]]:
    return [(group, [e for e in ENDPOINTS if e.group == group]) for group in GROUPS]


# ------------------------------------------------------------------ dispatch

ERRORS_BY_FAILURE = {
    keys.Failure.MALFORMED: ("invalid_key", "The API key is malformed."),
    keys.Failure.UNKNOWN: ("invalid_key", "The API key is not valid."),
    keys.Failure.REVOKED: ("revoked_key", "The API key has been revoked."),
    keys.Failure.EXPIRED: ("expired_key", "The API key has expired."),
    keys.Failure.INACTIVE_USER: ("inactive_user", "The key's user account is disabled."),
}


def authenticate(request: HttpRequest) -> Call:
    """
    The Bearer key of the request, and nothing else: cookies and sessions
    are ignored on the API, so a browser session (and with it CSRF) cannot
    act on it.
    """
    header = request.headers.get("Authorization", "")
    if not header:
        raise unauthorized(
            "missing_key", "Send an API key in the header 'Authorization: Bearer <key>'."
        )
    scheme, _, raw_key = header.partition(" ")
    if scheme.lower() != "bearer" or not raw_key.strip():
        raise unauthorized("invalid_key", "Use the header 'Authorization: Bearer <key>'.")
    outcome = keys.authenticate(raw_key.strip())
    if isinstance(outcome, keys.Failure):
        raise unauthorized(*ERRORS_BY_FAILURE[outcome])
    # Anything downstream that reads request.user sees the key's user, not
    # whatever a session cookie might carry.
    request.user = outcome.user
    return Call(request=request, user=outcome.user, key=outcome.key)


def rate_limit(call: Call) -> dict[str, str]:
    capacity: int = settings.YARADUDE_API_RATE_LIMIT
    window: int = settings.YARADUDE_API_RATE_WINDOW
    if capacity <= 0:
        return {}
    directory = Path(settings.YARADUDE_API_RATE_DIR)
    decision = ratelimit.take(directory, call.key.public_id, capacity, window)
    headers = {
        "RateLimit-Limit": str(capacity),
        "RateLimit-Remaining": str(decision.remaining),
    }
    if not decision.allowed:
        raise ApiError(
            429,
            "rate_limited",
            f"Too many requests for this key: at most {capacity} per {window} seconds.",
            headers={**headers, "Retry-After": str(decision.retry_after)},
        )
    return headers


def dispatch(request: HttpRequest, methods: dict[str, Endpoint], kwargs: dict[str, Any]):
    headers: dict[str, str] = {}
    try:
        call = authenticate(request)
        headers = rate_limit(call)
        method = "GET" if request.method == "HEAD" else (request.method or "")
        selected = methods.get(method)
        if selected is None:
            allowed = ", ".join(sorted(methods))
            raise ApiError(
                405,
                "method_not_allowed",
                f"{request.method} is not allowed here; use {allowed}.",
                headers={"Allow": allowed},
            )
        missing = [p for p in selected.permissions if not call.user.has_perm(p)]
        if missing:
            raise ApiError(
                403,
                "permission_denied",
                "Your account lacks the permission for this: "
                + ", ".join(missing)
                + ". Ask an administrator for the Viewers or Editors role.",
            )
        response = selected.handler(call, **kwargs)
    except ApiError as error:
        response = error.response()
    except Http404 as error:
        response = ApiError(404, "not_found", str(error) or "Not found.").response()
    except PermissionDenied as error:
        response = ApiError(403, "permission_denied", str(error) or "Permission denied.").response()
    except RequestDataTooBig:
        response = ApiError(413, "too_large", "The request body is too large.").response()
    except (SuspiciousOperation, UnreadablePostError):
        response = ApiError(400, "bad_request", "The request could not be read.").response()
    except Exception:
        # Logged without the request body, headers or key.
        logger.exception("Unhandled error in API %s %s", request.method, request.path)
        response = ApiError(500, "server_error", "Internal server error.").response()
    for name, value in headers.items():
        response.setdefault(name, value)
    if request.method == "HEAD":
        response.content = b""  # ty: ignore[invalid-assignment]  # HttpResponse.content has a setter; django-types 0.24 declares it read-only
    return response


def _route_view(methods: dict[str, Endpoint]) -> Callable[..., HttpResponse]:
    def view(request: HttpRequest, **kwargs: Any) -> HttpResponse:
        return dispatch(request, methods, kwargs)

    # Bearer authentication only, so there is no cookie-based identity for a
    # cross-site request to borrow; the CSRF check would only refuse API
    # clients. LoginRequiredMiddleware's redirect is replaced by JSON 401.
    return login_not_required(csrf_exempt(view))


def urlpatterns() -> list[URLPattern]:
    """One pattern per endpoint (so every operation can be reversed), one view per route."""
    routes: dict[str, dict[str, Endpoint]] = {}
    for e in ENDPOINTS:
        routes.setdefault(e.route, {})[e.method] = e
    views = {route: _route_view(methods) for route, methods in routes.items()}
    return [path(e.route, views[e.route], name=e.operation) for e in ENDPOINTS]


@login_not_required
@csrf_exempt
def not_found(request: HttpRequest, rest: str = "") -> HttpResponse:
    """JSON 404 for every other URL below /api/ (instead of the HTML page or a login redirect)."""
    message = "No such API endpoint."
    if not request.path.endswith("/"):
        message += " API paths end with a slash."
    return ApiError(404, "not_found", message).response()
