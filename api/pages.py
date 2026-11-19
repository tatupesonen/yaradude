"""
The API's pages in the web UI: the documentation (any signed-in user) and
the key management page (each user manages their own keys). These are
ordinary session-authenticated pages outside /api/.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.contrib import messages
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils.decorators import method_decorator
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_POST, require_safe
from django.views.generic import TemplateView

from accounts.roles import VIEWER_PERMISSIONS
from api import examples, keys
from api.forms import ApiKeyForm
from api.models import ApiKey
from api.openapi import base_url, openapi_document
from api.registry import GROUP_INTROS, GROUPS, PREFIX, Endpoint, by_group
from rules.services import importer
from rules.views.base import current_user

VIEWER_SET = {f"rules.{codename}" for codename in VIEWER_PERMISSIONS}


def who_can(e: Endpoint) -> str:
    if not e.permissions:
        return "Any valid key"
    if set(e.permissions) <= VIEWER_SET:
        return "Viewers and Editors"
    return "Editors"


@dataclass(frozen=True)
class Documented:
    endpoint: Endpoint
    full_path: str
    who: str
    allowed: bool
    example: examples.Example


def slug(group: str) -> str:
    return group.lower()


def nav(active: str) -> list[dict[str, Any]]:
    return [
        {"slug": "", "title": "Overview", "active": active == ""},
        *(
            {"slug": slug(group), "title": group, "active": active == slug(group)}
            for group in GROUPS
        ),
    ]


class DocsView(TemplateView):
    """Overview: base URL, keys, conventions; the endpoint index."""

    template_name = "api/docs.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        return super().get_context_data(
            base_url=base_url(self.request),
            server_url=self.request.build_absolute_uri("/"),
            nav=nav(""),
            rate_limit=settings.YARADUDE_API_RATE_LIMIT,
            rate_window=settings.YARADUDE_API_RATE_WINDOW,
            scan_max=settings.YARADUDE_SCAN_MAX_BYTES,
            rule_file_max=importer.max_file_bytes(),
            groups=[
                {
                    "title": group,
                    "slug": slug(group),
                    "intro": GROUP_INTROS[group],
                    "endpoints": endpoints,
                }
                for group, endpoints in by_group()
            ],
            **kwargs,
        )


class DocsGroupView(TemplateView):
    """Reference of one group of endpoints, with examples."""

    template_name = "api/docs_group.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        wanted = kwargs.pop("group")
        group = next((g for g in GROUPS if slug(g) == wanted), None)
        if group is None:
            raise Http404("No such API section.")
        user = current_user(self.request)
        api_base = base_url(self.request)
        endpoints = dict(by_group())[group]
        documented = [
            Documented(
                endpoint=e,
                full_path=PREFIX + e.path,
                who=who_can(e),
                allowed=all(user.has_perm(p) for p in e.permissions),
                example=examples.example(e, api_base),
            )
            for e in endpoints
        ]
        return super().get_context_data(
            group=group,
            intro=GROUP_INTROS[group],
            nav=nav(slug(group)),
            documented=documented,
            **kwargs,
        )


@require_safe
def openapi_download(request: HttpRequest) -> JsonResponse:
    """The OpenAPI document for signed-in users (the API itself needs a key)."""
    return JsonResponse(
        openapi_document(request),
        headers={"Content-Disposition": 'inline; filename="yaradude-openapi.json"'},
    )


@require_safe
def client_download(request: HttpRequest) -> HttpResponse:
    """The stdlib client module used by the Python examples, set to this server."""
    return HttpResponse(
        examples.client_source(request.build_absolute_uri("/")),
        content_type="text/x-python; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="yaradude_client.py"'},
    )


@method_decorator(never_cache, name="dispatch")
class KeysView(TemplateView):
    """List, create and revoke the signed-in user's own keys."""

    template_name = "api/keys.html"

    def get_context_data(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.setdefault("form", ApiKeyForm())
        user = current_user(self.request)
        return super().get_context_data(
            api_keys=ApiKey.objects.filter(user=user),
            max_keys=keys.max_keys(),
            nav=nav("keys"),
            nav_keys=True,
            **kwargs,
        )

    def post(self, request: HttpRequest) -> HttpResponse:
        form = ApiKeyForm(request.POST)
        if form.is_valid():
            try:
                key, secret = keys.create_key(
                    current_user(request), form.cleaned_data["name"], form.expires_in()
                )
            except keys.TooManyKeys as error:
                form.add_error(None, str(error))
            else:
                # Rendered directly (not stored, not redirected): this response
                # is the only place the key ever appears.
                return self.render_to_response(
                    self.get_context_data(form=ApiKeyForm(), new_key=key, secret=secret),
                    status=201,
                )
        return self.render_to_response(self.get_context_data(form=form), status=400)


@require_POST
def revoke(request: HttpRequest, pk: int) -> HttpResponse:
    key = get_object_or_404(ApiKey, pk=pk, user=current_user(request))
    keys.revoke_key(key)
    messages.success(request, f"Revoked the key {key.prefix} ({key.name}).")
    return redirect("api:keys")
