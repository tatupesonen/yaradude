"""Task queue names (PLAN.md 12.9). Workers are assigned to exactly one queue."""

SCAN_QUEUE = "scans"  # scan jobs; served by the scan workers
MAINTENANCE_QUEUE = "maintenance"  # directory passes, cleanup and other housekeeping

QUEUES = [SCAN_QUEUE, MAINTENANCE_QUEUE]
