from django.apps import AppConfig
from django.utils.module_loading import autodiscover_modules


class ScansConfig(AppConfig):
    name = "scans"
    verbose_name = "Scan jobs"

    def ready(self) -> None:
        from scans import recurring

        recurring.connect_signals()
        # Every app's `tasks` module, so recurring tasks are registered in
        # every process (web, workers) before anything schedules them.
        autodiscover_modules("tasks")
