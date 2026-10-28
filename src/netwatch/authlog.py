"""Detect SSH brute force from sshd's log.

The parsing and the sliding-window counting come from log-analyzer (a pinned dependency):
``SSHParser`` turns an sshd message into a failed or accepted login with the client address read
from sshd's own fields, counting each attempt once, and ``RateTracker`` counts failures per
address over a sliding window. This module decides what is worth an alert:

- **ssh-brute-force** (warning): ``max_failures`` failed logins from one address within the
  window. At most one per address per window, so a long attack doesn't raise an alert per try.
- **ssh-login-after-failures** (critical): a successful login from an address that raised a
  brute-force alert within the last window, the classic sign that the brute force worked. Once
  per brute-force alert: further logins from the address are the same incident.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from log_analyzer.core import RateTracker
from log_analyzer.parsers import SSHParser

from netwatch.journal import Record

OUTCOME_FAILED = "failed"
OUTCOME_ACCEPTED = "accepted"

KIND_BRUTE_FORCE = "ssh-brute-force"
KIND_LOGIN_AFTER_FAILURES = "ssh-login-after-failures"
ALERT_KINDS = (KIND_BRUTE_FORCE, KIND_LOGIN_AFTER_FAILURES)
SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"


@dataclass(frozen=True)
class AuthEvent:
    """One failed or successful SSH login, as sshd logged it."""

    ts_us: int  # when sshd logged it, microseconds since the Unix epoch
    source: str  # the client's address
    username: str
    outcome: str  # OUTCOME_FAILED or OUTCOME_ACCEPTED
    method: str | None  # password, publickey, ...; None when sshd didn't log one
    invalid_user: bool  # the account doesn't exist
    message: str
    cursor: str  # journal cursor of the entry; unique, so storing is idempotent


@dataclass(frozen=True)
class Alert:
    ts_us: int
    kind: str
    severity: str
    subject: str  # what the alert is about: here the client's address
    message: str


def _utc(ts_us: int) -> datetime:
    return datetime.fromtimestamp(ts_us / 1_000_000, UTC)


class AuthMonitor:
    """Feed sshd journal records in log order; get login events and the alerts they raise."""

    def __init__(self, max_failures: int, window_minutes: int) -> None:
        self.max_failures = max_failures
        self.window_minutes = window_minutes
        self._window_us = window_minutes * 60_000_000
        self._parser = SSHParser()
        self._failures = RateTracker(window_seconds=window_minutes * 60, max_events=max_failures)
        # Address -> time of its latest brute-force alert, for the cooldown and for spotting
        # a login after it. Entries older than the window are dropped, so this stays small.
        self._alerted_us: dict[str, int] = {}
        # Addresses whose current brute-force alert already raised a login alert.
        self._login_reported: set[str] = set()

    def restore(
        self,
        failures: Iterable[tuple[str, int]],
        alerts: Iterable[tuple[str, int]],
        login_alerts: Iterable[tuple[str, int]] = (),
    ) -> None:
        """Rebuild the current window after a restart from stored (address, time) pairs.

        ``alerts`` are brute-force alerts and ``login_alerts`` login-after-failures alerts.
        Without this, a restart would forget failures from just before it, and an attack that
        straddles the restart could stay under the threshold on both sides.
        """
        for source, ts_us in failures:
            self._failures.record(source, _utc(ts_us))
        for source, ts_us in alerts:
            self._alerted_us[source] = max(ts_us, self._alerted_us.get(source, ts_us))
        for source, ts_us in login_alerts:
            if source in self._alerted_us and ts_us >= self._alerted_us[source]:
                self._login_reported.add(source)

    def feed(self, record: Record) -> tuple[AuthEvent | None, list[Alert]]:
        parsed = self._parser.parse_line(record.message)
        if parsed is None or parsed.event_type not in (OUTCOME_FAILED, OUTCOME_ACCEPTED):
            return None, []
        event = AuthEvent(
            ts_us=record.ts_us,
            source=parsed.ip,
            username=parsed.extra.get("user", ""),
            outcome=parsed.event_type,
            method=parsed.extra.get("method"),
            invalid_user=bool(parsed.extra.get("invalid_user")),
            message=record.message,
            cursor=record.cursor,
        )
        self._forget_before(event.ts_us - self._window_us)
        if event.outcome == OUTCOME_FAILED:
            alerts = self._on_failure(event)
        else:
            alerts = self._on_login(event)
        return event, alerts

    def _on_failure(self, event: AuthEvent) -> list[Alert]:
        over_limit = self._failures.record(event.source, _utc(event.ts_us))
        if not over_limit or event.source in self._alerted_us:
            return []
        self._alerted_us[event.source] = event.ts_us
        self._login_reported.discard(event.source)
        return [
            Alert(
                ts_us=event.ts_us,
                kind=KIND_BRUTE_FORCE,
                severity=SEVERITY_WARNING,
                subject=event.source,
                message=f"{self.max_failures} or more failed SSH logins from {event.source}"
                f" within {self.window_minutes} minutes (latest as {event.username!r})",
            )
        ]

    def _on_login(self, event: AuthEvent) -> list[Alert]:
        if event.source not in self._alerted_us or event.source in self._login_reported:
            return []
        self._login_reported.add(event.source)
        return [
            Alert(
                ts_us=event.ts_us,
                kind=KIND_LOGIN_AFTER_FAILURES,
                severity=SEVERITY_CRITICAL,
                subject=event.source,
                message=f"successful SSH login as {event.username!r} from {event.source}"
                f" after a brute-force alert for it within {self.window_minutes} minutes",
            )
        ]

    def _forget_before(self, cutoff_us: int) -> None:
        for source in [s for s, ts in self._alerted_us.items() if ts <= cutoff_us]:
            del self._alerted_us[source]
            self._login_reported.discard(source)
