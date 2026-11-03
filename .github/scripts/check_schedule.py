#!/usr/bin/env python3
"""Evaluate the automation's calendar-day schedule and emit Actions outputs."""

from __future__ import annotations

import argparse
from datetime import date, datetime, timezone
from pathlib import Path


ANCHOR_DATE = date(2026, 10, 27)


def parse_bool(value: str) -> bool:
    """Parse the boolean strings emitted by GitHub expressions."""
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no", ""}:
        return False
    raise ValueError(f"invalid boolean value: {value!r}")


def parse_github_timestamp(value: str) -> datetime:
    """Parse GitHub's ISO-8601 run timestamp and require a timezone."""
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("run timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def schedule_decision(
    event: str, started_at: datetime, force_run: bool
) -> tuple[bool, str]:
    """Return eligibility and a human-readable reason."""
    if event == "workflow_dispatch":
        if force_run:
            return True, "Manual full run requested; the date guard was intentionally overridden."
        return False, "Manual guard-only test passed; Codex and PR creation were skipped."

    if event != "schedule":
        return False, f"Unsupported event {event!r}; failing closed."

    run_date = started_at.date()
    if run_date < ANCHOR_DATE:
        return False, f"Scheduled date {run_date} is before the 2026-10-27 start date."

    elapsed_days = (run_date - ANCHOR_DATE).days
    if elapsed_days % 2:
        return False, f"Scheduled date {run_date} is an off day in the 48-hour cadence."
    return True, f"Scheduled date {run_date} is day {elapsed_days} of the cadence and is eligible."


def append_lines(path: str, lines: list[str]) -> None:
    with Path(path).open("a", encoding="utf-8") as destination:
        destination.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--event", required=True)
    parser.add_argument("--started-at", required=True)
    parser.add_argument("--force-run", default="false")
    parser.add_argument("--github-output", required=True)
    parser.add_argument("--step-summary", required=True)
    args = parser.parse_args()

    started_at = parse_github_timestamp(args.started_at)
    eligible, reason = schedule_decision(
        args.event, started_at, parse_bool(args.force_run)
    )
    append_lines(
        args.github_output,
        [f"eligible={'true' if eligible else 'false'}", f"reason={reason}"],
    )
    append_lines(
        args.step_summary,
        ["### Schedule guard", reason, f"Run started at `{started_at.isoformat()}`."],
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
