"""Helpers shared by the endpoint modules."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from django.core.paginator import Page
from django.views.generic import TemplateView

from api.http import ApiError, Call
from api.registry import Param, Reply

PAGE = Param(
    "page",
    "Page number (1-based). Out-of-range or invalid numbers give the nearest page, as in the UI.",
    type="integer",
)

UNAUTHORIZED = Reply(
    401,
    "Missing, malformed, unknown, revoked or expired key, or the key's user is disabled.",
    schema="Error",
)
FORBIDDEN = Reply(403, "The key's user lacks the permission.", schema="Error")
NOT_FOUND = Reply(404, "No such object.", schema="Error")
INVALID = Reply(
    400, "The request is not valid; `fields` holds the messages per field.", schema="Error"
)
RATE_LIMITED = Reply(429, "Rate limit reached; retry after `Retry-After` seconds.", schema="Error")
COMMON_ERRORS = (UNAUTHORIZED, FORBIDDEN, RATE_LIMITED)


def page_data(call: Call, page: Page, serialize: Callable[[Any], dict[str, Any]]) -> dict:
    """The pagination envelope around one page of results."""
    paginator = page.paginator

    def link(number: int) -> str:
        query = call.request.GET.copy()
        query["page"] = str(number)
        return call.absolute(f"{call.request.path}?{query.urlencode()}")

    return {
        "count": paginator.count,
        "page": page.number,
        "pages": paginator.num_pages,
        "page_size": paginator.per_page,
        "next": link(page.next_page_number()) if page.has_next() else None,
        "previous": link(page.previous_page_number()) if page.has_previous() else None,
        "results": [serialize(item) for item in page.object_list],
    }


def ui_context(view_class: type[TemplateView], call: Call, **kwargs: Any) -> dict[str, Any]:
    """
    The context a UI page builds for this request: used where the UI's
    query logic still lives inside a view class (see PLAN.md 12.8, "Shared
    query logic"), so that the API reuses it instead of copying it.
    """
    view = view_class()
    view.setup(call.request, **kwargs)
    return view.get_context_data()


def text_field(data: dict[str, Any], name: str, *, required: bool = True) -> str:
    value = data.get(name)
    if value is None:
        if required:
            raise ApiError(
                400,
                "invalid",
                "The request is not valid.",
                fields={name: ["This field is required."]},
            )
        return ""
    if not isinstance(value, str):
        raise ApiError(
            400, "invalid", "The request is not valid.", fields={name: ["Must be a string."]}
        )
    return value


def int_field(data: dict[str, Any], name: str, *, required: bool = True) -> int | None:
    value = data.get(name)
    if value is None:
        if required:
            raise ApiError(
                400,
                "invalid",
                "The request is not valid.",
                fields={name: ["This field is required."]},
            )
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ApiError(
            400,
            "invalid",
            "The request is not valid.",
            fields={name: ["Must be a positive integer."]},
        )
    return value


def id_list(data: dict[str, Any], name: str) -> list[int]:
    value = data.get(name, [])
    if not isinstance(value, list) or not all(
        isinstance(item, int) and not isinstance(item, bool) and item > 0 for item in value
    ):
        raise ApiError(
            400,
            "invalid",
            "The request is not valid.",
            fields={name: ["Must be a list of positive integers."]},
        )
    return value
