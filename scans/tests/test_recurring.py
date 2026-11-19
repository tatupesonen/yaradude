from datetime import timedelta

from django.test import TestCase, override_settings
from django.utils import timezone
from django_tasks_db.models import DBTaskResult, get_date_max

from scans import recurring
from scans.models import RecurringSchedule, WorkerProcess
from scans.tasking import TaskResultStatus
from scans.tests import dummy_tasks
from scans.tests.helpers import drain, worker

TICK = dummy_tasks.tick.module_path
BOOM = dummy_tasks.boom.module_path


def pending(name: str) -> list[DBTaskResult]:
    return list(
        DBTaskResult.objects.filter(
            task_path=name, status__in=[TaskResultStatus.READY, TaskResultStatus.RUNNING]
        )
    )


@override_settings(TEST_RECURRING_INTERVAL=60)
class RecurringTests(TestCase):
    def setUp(self) -> None:
        dummy_tasks.calls.clear()

    def test_registered_tasks_include_cleanup_and_test_tasks(self) -> None:
        names = {entry.name for entry in recurring.registered()}
        self.assertIn("scans.tasks.cleanup_scan_jobs", names)
        self.assertIn(TICK, names)

    def test_one_pending_occurrence_however_often_ensured(self) -> None:
        for _ in range(3):
            recurring.ensure_scheduled(dummy_tasks.tick)
        recurring.ensure_all_scheduled()
        self.assertEqual(len(pending(TICK)), 1)
        status = recurring.status(TICK)
        self.assertTrue(status.enabled and status.waiting)
        self.assertIsNone(status.scheduled_for)  # never ran: due now
        self.assertEqual(status.runs, 0)

    def test_next_occurrence_after_success_waits_for_the_interval(self) -> None:
        recurring.ensure_scheduled(TICK)
        maintenance_worker = worker("maintenance")
        self.assertEqual(drain(maintenance_worker), 1)
        self.assertEqual(dummy_tasks.calls, ["tick"])
        status = recurring.status(TICK)
        self.assertEqual((status.runs, status.last_succeeded, status.last_error), (1, True, ""))
        assert status.last_started_at is not None and status.scheduled_for is not None
        self.assertEqual(status.scheduled_for, status.last_started_at + timedelta(seconds=60))
        self.assertEqual(len(pending(TICK)), 1)
        # Not due yet: the worker finds nothing to do.
        self.assertFalse(maintenance_worker.run_once())

    def test_next_occurrence_after_failure(self) -> None:
        recurring.ensure_scheduled(BOOM)
        with self.assertLogs("django.tasks", "ERROR"):
            drain(worker("maintenance"))
        status = recurring.status(BOOM)
        self.assertEqual(dummy_tasks.calls, ["boom"])
        self.assertEqual((status.runs, status.last_succeeded), (1, False))
        self.assertEqual(status.last_error, "builtins.RuntimeError")
        self.assertTrue(status.waiting)
        self.assertEqual(len(pending(BOOM)), 1)

    def test_a_pass_longer_than_the_interval_is_followed_once_at_once(self) -> None:
        recurring.ensure_scheduled(TICK)
        schedule = RecurringSchedule.objects.get(name=TICK)
        # Pretend the pass started two intervals ago.
        RecurringSchedule.objects.filter(pk=schedule.pk).update(
            last_started_at=timezone.now() - timedelta(seconds=120)
        )
        DBTaskResult.objects.filter(id=schedule.task_result_id).update(
            status=TaskResultStatus.SUCCESSFUL, finished_at=timezone.now()
        )
        recurring.ensure_scheduled(TICK)
        recurring.ensure_scheduled(TICK)
        waiting = pending(TICK)
        self.assertEqual(len(waiting), 1)
        self.assertEqual(waiting[0].run_after, get_date_max())  # due at once

    def test_lost_schedule_is_restored(self) -> None:
        recurring.ensure_scheduled(TICK)
        # Queue emptied.
        DBTaskResult.objects.all().delete()
        recurring.ensure_all_scheduled()
        self.assertEqual(len(pending(TICK)), 1)
        # Fresh database: no schedule row at all.
        RecurringSchedule.objects.all().delete()
        DBTaskResult.objects.all().delete()
        recurring.ensure_all_scheduled()
        self.assertEqual(len(pending(TICK)), 1)

    def test_occurrence_of_a_dead_worker_is_replaced(self) -> None:
        recurring.ensure_scheduled(TICK)
        schedule = RecurringSchedule.objects.get(name=TICK)
        DBTaskResult.objects.filter(id=schedule.task_result_id).update(
            status=TaskResultStatus.RUNNING, worker_ids=["gone"], started_at=timezone.now()
        )
        # Still running on a live worker: left alone.
        WorkerProcess.objects.create(worker_id="gone", role="maintenance")
        recurring.ensure_scheduled(TICK)
        self.assertEqual(recurring.status(TICK).running, True)
        # The worker stops sending heartbeats.
        WorkerProcess.objects.filter(worker_id="gone").update(
            last_seen=timezone.now() - timedelta(hours=1)
        )
        recurring.ensure_scheduled(TICK)
        old = DBTaskResult.objects.get(id=schedule.task_result_id)
        self.assertEqual(old.status, TaskResultStatus.FAILED)
        status = recurring.status(TICK)
        self.assertTrue(status.waiting)
        self.assertEqual(status.last_error, "worker lost")
        self.assertEqual(len(pending(TICK)), 1)

    def test_interval_zero_turns_it_off(self) -> None:
        recurring.ensure_scheduled(TICK)
        with override_settings(TEST_RECURRING_INTERVAL=0):
            status = recurring.ensure_scheduled(TICK)
            self.assertFalse(status.enabled or status.waiting or status.running)
            self.assertEqual(pending(TICK), [])
            recurring.ensure_all_scheduled()
            self.assertEqual(pending(TICK), [])

    def test_shorter_interval_pulls_the_waiting_occurrence_forward(self) -> None:
        recurring.ensure_scheduled(TICK)
        drain(worker("maintenance"))
        before = recurring.status(TICK).scheduled_for
        with override_settings(TEST_RECURRING_INTERVAL=10):
            after = recurring.ensure_scheduled(TICK).scheduled_for
        assert before is not None and after is not None
        self.assertLess(after, before)

    def test_run_now(self) -> None:
        recurring.ensure_scheduled(TICK)
        drain(worker("maintenance"))
        self.assertIsNotNone(recurring.status(TICK).scheduled_for)
        recurring.run_now(TICK)
        self.assertIsNone(recurring.status(TICK).scheduled_for)
        drain(worker("maintenance"))
        self.assertEqual(dummy_tasks.calls, ["tick", "tick"])

    def test_unknown_task(self) -> None:
        with self.assertRaises(LookupError):
            recurring.status("no.such.task")
