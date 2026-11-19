"""Root URL configuration: admin, authentication, health check and the rules app."""

from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from config.views import healthz

urlpatterns = [
    path("admin/", admin.site.urls),
    # Login, logout and password change from django.contrib.auth; the
    # email-based password reset views are left out (no email when air-gapped).
    path("accounts/login/", auth_views.LoginView.as_view(), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path(
        "accounts/password_change/",
        auth_views.PasswordChangeView.as_view(),
        name="password_change",
    ),
    path(
        "accounts/password_change/done/",
        auth_views.PasswordChangeDoneView.as_view(),
        name="password_change_done",
    ),
    path("healthz/", healthz, name="healthz"),
    path("", include("api.urls")),  # /api/v1/ (key auth), /api-docs/, /account/api-keys/
    path("", include("rules.urls")),
]
