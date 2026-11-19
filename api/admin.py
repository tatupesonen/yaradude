from django.contrib import admin
from django.http import HttpRequest

from api import keys
from api.models import ApiKey


@admin.register(ApiKey)
class ApiKeyAdmin(admin.ModelAdmin):
    """Administrators can see and revoke keys; they cannot create or read secrets."""

    list_display = [
        "prefix",
        "name",
        "user",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    ]
    list_filter = ["revoked_at"]
    search_fields = ["name", "public_id", "user__username"]
    readonly_fields = [
        "user",
        "name",
        "prefix",
        "created_at",
        "last_used_at",
        "expires_at",
        "revoked_at",
    ]
    fields = readonly_fields
    actions = ["revoke"]

    def has_add_permission(self, request: HttpRequest) -> bool:
        return False

    @admin.action(description="Revoke the selected keys")
    def revoke(self, request: HttpRequest, queryset) -> None:
        for key in queryset:
            keys.revoke_key(key)
