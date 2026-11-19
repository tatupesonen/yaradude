from django.apps import AppConfig


class ApiConfig(AppConfig):
    """HTTP API under /api/v1/ with personal API keys (PLAN.md section 12.8)."""

    name = "api"
    verbose_name = "API"

    def ready(self) -> None:
        # Importing the endpoint modules registers their routes.
        from api import endpoints  # noqa: F401
