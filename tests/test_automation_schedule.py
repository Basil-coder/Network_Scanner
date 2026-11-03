from datetime import datetime, timezone
import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "check_schedule.py"
SPEC = importlib.util.spec_from_file_location("check_schedule", SCRIPT)
assert SPEC and SPEC.loader
check_schedule = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(check_schedule)


def at(year: int, month: int, day: int) -> datetime:
    return datetime(year, month, day, 13, 15, tzinfo=timezone.utc)


class ScheduleDecisionTests(unittest.TestCase):
    def test_starts_on_27_october_2026(self) -> None:
        eligible, _ = check_schedule.schedule_decision(
            "schedule", at(2026, 10, 27), False
        )
        self.assertTrue(eligible)

    def test_rejects_day_before_start(self) -> None:
        eligible, _ = check_schedule.schedule_decision(
            "schedule", at(2026, 10, 26), False
        )
        self.assertFalse(eligible)

    def test_alternates_across_month_boundary(self) -> None:
        expected = {
            (2026, 10, 30): False,
            (2026, 10, 31): True,
            (2026, 11, 1): False,
            (2026, 11, 2): True,
        }
        for date_parts, is_eligible in expected.items():
            with self.subTest(date_parts=date_parts):
                actual, _ = check_schedule.schedule_decision(
                    "schedule", at(*date_parts), False
                )
                self.assertEqual(is_eligible, actual)

    def test_manual_default_is_guard_only(self) -> None:
        eligible, _ = check_schedule.schedule_decision(
            "workflow_dispatch", at(2026, 10, 25), False
        )
        self.assertFalse(eligible)

    def test_manual_override_runs_before_anchor(self) -> None:
        eligible, _ = check_schedule.schedule_decision(
            "workflow_dispatch", at(2026, 10, 25), True
        )
        self.assertTrue(eligible)

    def test_unknown_event_fails_closed(self) -> None:
        eligible, _ = check_schedule.schedule_decision("push", at(2026, 10, 27), True)
        self.assertFalse(eligible)


if __name__ == "__main__":
    unittest.main()
