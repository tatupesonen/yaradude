from django.apps import AppConfig, apps
from django.db.models.signals import post_migrate


class AccountsConfig(AppConfig):
    name = "accounts"

    def ready(self) -> None:
        from accounts.roles import ensure_roles

        # django.contrib.auth connects its permission creation earlier (it is
        # listed first in INSTALLED_APPS), so the rules permissions exist by
        # the time this receiver runs for the rules app.
        post_migrate.connect(
            ensure_roles,
            sender=apps.get_app_config("rules"),
            dispatch_uid="accounts.ensure_roles",
        )
