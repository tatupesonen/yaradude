"""Tasks of the scans app (Django Tasks, django-tasks-db backend)."""

from scans import maintenance, services
from scans.queues import MAINTENANCE_QUEUE, SCAN_QUEUE
from scans.recurring import recurring
from scans.tasking import task


@task(queue_name=SCAN_QUEUE)
def run_scan_job(job_id: str) -> None:
    """Scan one queued job. The only argument is the job id; no sample data."""
    services.execute_job(job_id)


@recurring("YARADUDE_SCAN_CLEANUP_INTERVAL")
@task(queue_name=MAINTENANCE_QUEUE)
def cleanup_scan_jobs() -> None:
    """Retention cleanup plus a repair pass (lost jobs, orphaned spool files)."""
    maintenance.cleanup()
    maintenance.repair()
