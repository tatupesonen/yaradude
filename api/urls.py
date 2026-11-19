"""
URLs of the api app: the API itself below /api/v1/ (Bearer keys only), a
JSON 404 for anything else below /api/, and the session-authenticated pages
for documentation and key management.
"""

from django.urls import include, path, re_path

from api import pages, registry

app_name = "api"

urlpatterns = [
    path("api/v1/", include(registry.urlpatterns())),
    re_path(r"^api/(?P<rest>.*)$", registry.not_found, name="not_found"),
    path("api-docs/", pages.DocsView.as_view(), name="docs"),
    path("api-docs/openapi.json", pages.openapi_download, name="docs_openapi"),
    path("api-docs/yaradude_client.py", pages.client_download, name="docs_client"),
    path("api-docs/<slug:group>/", pages.DocsGroupView.as_view(), name="docs_group"),
    path("account/api-keys/", pages.KeysView.as_view(), name="keys"),
    path("account/api-keys/<int:pk>/revoke/", pages.revoke, name="key_revoke"),
]
