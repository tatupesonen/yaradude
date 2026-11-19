"""Account: who am I, and the OpenAPI description."""

from __future__ import annotations

from django.http import HttpResponse

from api import serializers
from api.endpoints.common import COMMON_ERRORS
from api.http import Call, json_response
from api.openapi import openapi_document
from api.registry import Reply, endpoint


@endpoint(
    "GET",
    "me/",
    operation="me",
    group="Account",
    summary="Who am I",
    replies=(
        Reply(200, "The key's user, roles, permissions and the key itself.", schema="Me"),
        *COMMON_ERRORS,
    ),
    description="Works with any valid key, also for a user without a role.",
)
def me(call: Call) -> HttpResponse:
    user = call.user
    return json_response(
        {
            "username": user.get_username(),
            "name": user.get_full_name(),
            "email": user.email,
            "is_staff": user.is_staff,
            "roles": sorted(user.groups.values_list("name", flat=True)),
            "permissions": sorted(p for p in user.get_all_permissions() if p.startswith("rules.")),
            "key": serializers.api_key(call.key),
        }
    )


@endpoint(
    "GET",
    "openapi.json",
    operation="openapi",
    group="Account",
    summary="OpenAPI description",
    replies=(Reply(200, "This API as an OpenAPI 3.1 document.", schema="OpenAPI"), *COMMON_ERRORS),
    description="Machine-readable description of every endpoint, generated from the same "
    "declarations as the routes. Signed-in users can also download it from the API pages.",
)
def openapi(call: Call) -> HttpResponse:
    return json_response(openapi_document(call.request))
