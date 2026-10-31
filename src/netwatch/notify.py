"""Send Netwatch's alerts to Telegram (netwatch-notify).

The detectors write alerts to the shared ``alerts`` table. This service picks up the ones it has
not dealt with yet, sends each as a Telegram message and sets ``notified_us``. It polls every ten
seconds: SQLite has no change notifications, and ten seconds is quick enough for a message read on
a phone.

Delivery is at least once. ``notified_us`` is set only after Telegram has accepted the message,
so alerts raised while Telegram or the internet is unreachable go out once it is back. A crash
between Telegram's answer and the commit would send that one message twice.

Not every alert becomes a message of its own:

- **Baseline.** The first start records the time; alerts raised before it are never sent, so
  turning notifications on for a host with history does not replay weeks of old alerts.
- **Cooldown.** A repeat of an alert (same kind, same subject) within the cooldown of the last
  message about it is held back ("suppressed"); the first repeat after the cooldown is sent. The
  detectors already raise one alert per incident, so this is the second line of defence.
- **Bursts.** At most ten messages a minute. When more alerts are waiting than that allows, they
  go out as one summary message ("summarised") instead of one each.

``notified_us`` therefore means "dealt with": sent, summarised or suppressed. The counts of each
are kept in ``meta`` for the metrics, and every decision is logged.

The notifier also detects one thing itself: a restart of its host. It records a heartbeat every
minute; on start, a heartbeat from before the host booted means the host was down in between.
Both Netwatch VMs run on one desktop PC, so nothing can send an alert while that PC is off, and
the ``restart`` alert is the next best thing: when it went quiet, when it came back.
"""

from __future__ import annotations

import json
import logging
import socket
import sqlite3
import threading
import time
from collections import Counter, deque
from collections.abc import Callable, Mapping, Sequence
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, tzinfo
from typing import Protocol

from netwatch import alerts, storage
from netwatch.alerts import SEVERITY_CRITICAL, SEVERITY_WARNING, Alert, StoredAlert
from netwatch.config import Settings
from netwatch.errors import ConfigError, NetwatchError
from netwatch.ingest import DB_NAME
from netwatch.telegram import Bot, TelegramError, read_token

KIND_RESTART = "restart"
KIND_TEST = "test"
ALERT_KINDS = (KIND_RESTART, KIND_TEST)  # the notifier's own alerts, which it prunes
NO_COOLDOWN = frozenset(ALERT_KINDS)  # every test and every restart is worth a message

BASELINE_KEY = "notify.baseline_us"
HEARTBEAT_KEY = "notify.heartbeat_us"
LAST_SENT_KEY = "notify.last_sent"
COUNTS_KEY = "notify.counts"
ERRORS_KEY = "notify.telegram_errors"

RESULT_SENT = "sent"
RESULT_SUPPRESSED = "suppressed"
RESULT_SUMMARISED = "summarised"
RESULTS = (RESULT_SENT, RESULT_SUPPRESSED, RESULT_SUMMARISED)

POLL_S = 10.0
HEARTBEAT_S = 60.0
PRUNE_S = 6 * 3600.0
MAX_PER_MINUTE = 10
BATCH = 500
RETENTION_DAYS = 90
BACKOFF_MIN_S = 10.0
BACKOFF_MAX_S = 300.0
TEST_TIMEOUT_S = 30.0
DEFAULT_TEST_TEXT = "Test message from netwatch notify test: notifications work."

_MARK = {SEVERITY_CRITICAL: "\U0001f534", SEVERITY_WARNING: "\U0001f7e1"}  # red, yellow circle
_TEST_MARK = "✅"  # check mark

log = logging.getLogger("netwatch.notify")


class Sender(Protocol):
    def send(self, chat_id: int, text: str, *, silent: bool = False) -> None: ...


def _wall_us() -> int:
    return time.time_ns() // 1000


def boot_time_us() -> int:
    """When the host booted: now minus the time since boot (Linux only).

    Read from the clocks rather than /proc/stat, which the service's sandbox hides.
    """
    return _wall_us() - time.clock_gettime_ns(time.CLOCK_BOOTTIME) // 1000


def require_chat_id(settings: Settings) -> int:
    if settings.telegram_chat_id is None:
        raise ConfigError(
            "notifications are off: set NETWATCH_TELEGRAM_CHAT_ID in /etc/netwatch/netwatch.env"
            " (docs/alerting.md)"
        )
    return settings.telegram_chat_id


# --- Message text -------------------------------------------------------------------------------


def _local(ts_us: int, tz: tzinfo | None) -> datetime:
    when = datetime.fromtimestamp(ts_us / 1_000_000, tz)
    return when if tz is not None else when.astimezone()


def _clock(ts_us: int, now_us: int, tz: tzinfo | None) -> str:
    """A time of day, with the date when it isn't today."""
    when = _local(ts_us, tz)
    same_day = when.date() == _local(now_us, tz).date()
    return when.strftime("%H:%M:%S %Z" if same_day else "%d %b %H:%M %Z").strip()


def _duration(seconds: float) -> str:
    minutes = round(seconds / 60)
    if minutes < 1:
        return "under a minute"
    if minutes < 60:
        return f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} h {minutes} min" if minutes else f"{hours} h"
    return f"{hours // 24} days"


def format_alert(alert: StoredAlert, hostname: str, now_us: int, tz: tzinfo | None = None) -> str:
    if alert.kind == KIND_TEST:
        head = f"{_TEST_MARK} TEST"
    else:
        head = f"{_MARK.get(alert.severity, '-')} {alert.severity.upper()}: {alert.kind}"
    return f"{head}\n{alert.message}\n{hostname}, {_clock(alert.ts_us, now_us, tz)}"


def format_summary(
    batch: Sequence[StoredAlert], hostname: str, now_us: int, tz: tzinfo | None = None
) -> str:
    kinds = Counter(a.kind for a in batch)
    listed = ", ".join(
        f"{n} {kind}" for kind, n in sorted(kinds.items(), key=lambda item: (-item[1], item[0]))
    )
    critical = any(a.severity == SEVERITY_CRITICAL for a in batch)
    mark = _MARK[SEVERITY_CRITICAL if critical else SEVERITY_WARNING]
    first, last = batch[0].ts_us, batch[-1].ts_us
    span = _clock(first, now_us, tz)
    if last != first:
        span += f" to {_clock(last, now_us, tz)}"
    return (
        f"{mark} {len(batch)} alerts at once: {listed}\n"
        f"Raised {span}. Too many to send one by one; list them on the host with: netwatch alerts\n"
        f"{hostname}"
    )


def restart_message(boot_us: int, beat_us: int, now_us: int, tz: tzinfo | None = None) -> str:
    return (
        f"The host restarted: last heartbeat {_clock(beat_us, now_us, tz)}, booted"
        f" {_clock(boot_us, now_us, tz)}, down for about {_duration((boot_us - beat_us) / 1e6)}."
        " Nothing on it could alert in between."
    )


def _silent(alerts_: Sequence[StoredAlert]) -> bool:
    """Warnings arrive without a sound; a critical alert or a test makes the phone buzz."""
    return not any(a.severity == SEVERITY_CRITICAL or a.kind == KIND_TEST for a in alerts_)


# --- State kept in meta -------------------------------------------------------------------------


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    """How many alerts the notifier has sent, suppressed and summarised so far."""
    value = storage.get_meta(conn, COUNTS_KEY)
    found = {result: 0 for result in RESULTS}
    if value is not None:
        found.update({str(k): int(v) for k, v in json.loads(value).items()})
    return found


def telegram_errors(conn: sqlite3.Connection) -> int:
    """How many send attempts Telegram did not accept, or could not be reached for."""
    return int(storage.get_meta(conn, ERRORS_KEY) or 0)


@dataclass(frozen=True)
class Status:
    chat_id: int | None
    baseline_us: int | None
    heartbeat_us: int | None
    counts: dict[str, int]
    telegram_errors: int
    unsent: int
    oldest_unsent_us: int | None


def status(conn: sqlite3.Connection, settings: Settings) -> Status:
    baseline = storage.get_meta(conn, BASELINE_KEY)
    beat = storage.get_meta(conn, HEARTBEAT_KEY)
    unsent, oldest = (0, None) if baseline is None else alerts.unsent_summary(conn, int(baseline))
    return Status(
        chat_id=settings.telegram_chat_id,
        baseline_us=None if baseline is None else int(baseline),
        heartbeat_us=None if beat is None else int(beat),
        counts=counts(conn),
        telegram_errors=telegram_errors(conn),
        unsent=unsent,
        oldest_unsent_us=oldest,
    )


# --- The notifier -------------------------------------------------------------------------------


class Notifier:
    def __init__(
        self,
        conn: sqlite3.Connection,
        sender: Sender,
        chat_id: int,
        cooldown_minutes: int,
        hostname: str,
        wall_us: Callable[[], int] = _wall_us,
        monotonic: Callable[[], float] = time.monotonic,
        tz: tzinfo | None = None,
    ) -> None:
        self._conn = conn
        self._sender = sender
        self._chat_id = chat_id
        self._cooldown_us = cooldown_minutes * 60_000_000
        self._hostname = hostname
        self._wall_us = wall_us
        self._monotonic = monotonic
        self._tz = tz
        self._sent_at: deque[float] = deque()  # when the messages of the last minute went out
        self._retry_at = 0.0
        self._backoff_s = 0.0
        value = storage.get_meta(conn, LAST_SENT_KEY)
        self._last_sent: dict[tuple[str, str], int] = {
            (kind, subject): int(ts) for kind, subject, ts in json.loads(value or "[]")
        }

    def start(self, boot_us: int) -> Alert | None:
        """Record the baseline on the first start; raise a restart alert after a reboot."""
        now_us = self._wall_us()
        raised = None
        with storage.transaction(self._conn):
            if storage.get_meta(self._conn, BASELINE_KEY) is None:
                storage.put_meta(self._conn, BASELINE_KEY, str(now_us))
                earlier, _ = alerts.unsent_summary(self._conn, 0)
                log.info("first start: the %d alerts raised before now will not be sent", earlier)
            else:
                beat = storage.get_meta(self._conn, HEARTBEAT_KEY)
                if beat is not None and int(beat) < boot_us:
                    raised = Alert(
                        ts_us=now_us,
                        kind=KIND_RESTART,
                        severity=SEVERITY_WARNING,
                        subject=self._hostname,
                        message=restart_message(boot_us, int(beat), now_us, self._tz),
                    )
                    alerts.add(self._conn, raised)
            storage.put_meta(self._conn, HEARTBEAT_KEY, str(now_us))
        if raised is not None:
            log.warning("ALERT %s %s: %s", raised.severity, raised.kind, raised.message)
        return raised

    def heartbeat(self) -> None:
        storage.set_meta(self._conn, HEARTBEAT_KEY, str(self._wall_us()))

    def prune(self) -> int:
        cutoff = self._wall_us() - RETENTION_DAYS * 86_400_000_000
        with storage.transaction(self._conn):
            return alerts.prune(self._conn, cutoff, ALERT_KINDS)

    def poll(self) -> int:
        """Deal with the alerts waiting to be sent. Returns how many messages went out."""
        now = self._monotonic()
        if now < self._retry_at:
            return 0
        while self._sent_at and now - self._sent_at[0] >= 60:
            self._sent_at.popleft()
        budget = MAX_PER_MINUTE - len(self._sent_at)
        if budget <= 0:
            return 0
        baseline = int(storage.get_meta(self._conn, BASELINE_KEY) or 0)
        pending = alerts.unsent(self._conn, baseline, BATCH)
        if not pending:
            return 0
        fresh, repeats = self._split(pending)
        sent = 0
        if len(fresh) > budget:
            text = format_summary(fresh, self._hostname, self._wall_us(), self._tz)
            if self._deliver(text, fresh, RESULT_SUMMARISED):
                sent = 1
        else:
            for alert in fresh:
                text = format_alert(alert, self._hostname, self._wall_us(), self._tz)
                if not self._deliver(text, [alert], RESULT_SENT):
                    break
                sent += 1
        self._suppress(repeats)
        return sent

    def _split(self, pending: Sequence[StoredAlert]) -> tuple[list[StoredAlert], list[StoredAlert]]:
        """(alerts to send, repeats to hold back), assuming the ones to send will go out."""
        now_us = self._wall_us()
        last_sent = dict(self._last_sent)
        fresh, repeats = [], []
        for alert in pending:
            key = (alert.kind, alert.subject)
            last = last_sent.get(key)
            if alert.kind in NO_COOLDOWN or last is None or now_us - last >= self._cooldown_us:
                fresh.append(alert)
                last_sent[key] = now_us
            else:
                repeats.append(alert)
        return fresh, repeats

    def _deliver(self, text: str, handled: Sequence[StoredAlert], result: str) -> bool:
        try:
            self._sender.send(self._chat_id, text, silent=_silent(handled))
        except TelegramError as exc:
            self._failed(exc)
            return False
        self._sent_at.append(self._monotonic())
        self._backoff_s = 0.0
        now_us = self._wall_us()
        for alert in handled:
            self._last_sent[(alert.kind, alert.subject)] = now_us
        self._record(handled, result, now_us)
        return True

    def _suppress(self, repeats: Sequence[StoredAlert]) -> None:
        """Hold back repeats whose first alert really went out; the others wait for it."""
        now_us = self._wall_us()
        held = []
        for alert in repeats:
            last = self._last_sent.get((alert.kind, alert.subject))
            if last is not None and now_us - last < self._cooldown_us:
                held.append(alert)
        if held:
            self._record(held, RESULT_SUPPRESSED, now_us)

    def _record(self, handled: Sequence[StoredAlert], result: str, now_us: int) -> None:
        recent = sorted(
            [kind, subject, ts]
            for (kind, subject), ts in self._last_sent.items()
            if now_us - ts < self._cooldown_us
        )
        with storage.transaction(self._conn):
            alerts.mark_notified(self._conn, [a.id for a in handled], now_us)
            totals = counts(self._conn)
            totals[result] = totals.get(result, 0) + len(handled)
            storage.put_meta(self._conn, COUNTS_KEY, json.dumps(totals, sort_keys=True))
            storage.put_meta(self._conn, LAST_SENT_KEY, json.dumps(recent))
        for alert in handled:
            log.info("%s alert %d (%s, %s)", result, alert.id, alert.kind, alert.subject)

    def _failed(self, exc: TelegramError) -> None:
        with storage.transaction(self._conn):
            storage.put_meta(self._conn, ERRORS_KEY, str(telegram_errors(self._conn) + 1))
        if exc.retry_after is not None:
            wait = exc.retry_after
        elif exc.temporary:
            self._backoff_s = min(max(self._backoff_s * 2, BACKOFF_MIN_S), BACKOFF_MAX_S)
            wait = self._backoff_s
        else:
            wait = BACKOFF_MAX_S
        self._retry_at = self._monotonic() + wait
        if exc.temporary:
            log.warning("%s; trying again in %.0f s", exc, wait)
        else:
            log.error(
                "%s; check the bot token and NETWATCH_TELEGRAM_CHAT_ID (docs/alerting.md);"
                " trying again in %.0f s",
                exc,
                wait,
            )


def run(
    settings: Settings,
    stop: threading.Event,
    environ: Mapping[str, str],
    sender: Sender | None = None,
    boot_us: int | None = None,
    monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Send alerts until ``stop`` is set. Returns the exit code."""
    chat_id = require_chat_id(settings)
    if sender is None:
        sender = Bot(read_token(settings, environ), settings.telegram_api_url)
    with closing(storage.connect(settings.state_dir / DB_NAME)) as conn:
        notifier = Notifier(
            conn,
            sender,
            chat_id,
            settings.notify_cooldown_minutes,
            socket.gethostname(),
            monotonic=monotonic,
        )
        notifier.start(boot_time_us() if boot_us is None else boot_us)
        log.info(
            "sending alerts to Telegram chat %d; repeats held back for %d minutes",
            chat_id,
            settings.notify_cooldown_minutes,
        )
        next_beat = monotonic() + HEARTBEAT_S
        next_prune = monotonic()
        while True:
            notifier.poll()
            now = monotonic()
            if now >= next_beat:
                notifier.heartbeat()
                next_beat = now + HEARTBEAT_S
            if now >= next_prune:
                notifier.prune()
                next_prune = now + PRUNE_S
            if stop.wait(POLL_S):
                break
        log.info("stopped")
    return 0


def send_test(
    settings: Settings,
    text: str = DEFAULT_TEST_TEXT,
    timeout_s: float = TEST_TIMEOUT_S,
    wall_us: Callable[[], int] = _wall_us,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> StoredAlert:
    """Queue a test alert and wait until netwatch-notify has sent it.

    Going through the running service, rather than sending from this command, tests what the
    real alerts depend on: the service, its token, its sandbox and its network access.
    """
    require_chat_id(settings)
    path = settings.state_dir / DB_NAME
    if not path.exists():
        raise NetwatchError(f"no database at {path} (is a netwatch service running?)")
    with closing(storage.connect(path)) as conn:
        if storage.get_meta(conn, BASELINE_KEY) is None:
            raise NetwatchError(
                "netwatch-notify has never run on this host; run install.sh after setting it up"
                " (docs/alerting.md)"
            )
        alert = Alert(wall_us(), KIND_TEST, SEVERITY_WARNING, "netwatch", text)
        with storage.transaction(conn):
            alert_id = alerts.add(conn, alert)
        deadline = monotonic() + timeout_s
        while True:
            stored = alerts.get(conn, alert_id)
            if stored is not None and stored.notified_us is not None:
                return stored
            if monotonic() >= deadline:
                raise NetwatchError(
                    f"test alert {alert_id} is queued, but netwatch-notify did not send it within"
                    f" {timeout_s:.0f} s (systemctl status netwatch-notify;"
                    " journalctl -u netwatch-notify)"
                )
            sleep(1.0)
