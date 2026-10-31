from __future__ import annotations

import sqlite3
import sys
import threading
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC
from pathlib import Path

import pytest

from netwatch import alerts, notify, storage
from netwatch.alerts import SEVERITY_CRITICAL, SEVERITY_WARNING, Alert
from netwatch.config import load_settings
from netwatch.errors import ConfigError, NetwatchError
from netwatch.notify import Notifier
from netwatch.telegram import TelegramError

T0 = 1_793_000_000_000_000  # 2026-10-26, in microseconds
MINUTE = 60_000_000


class Clock:
    """Wall time in microseconds and a monotonic clock in seconds, moved together."""

    def __init__(self) -> None:
        self.us = T0

    def wall(self) -> int:
        return self.us

    def mono(self) -> float:
        return self.us / 1_000_000

    def advance(self, seconds: float) -> None:
        self.us += int(seconds * 1_000_000)


class FakeTelegram:
    def __init__(self) -> None:
        self.messages: list[tuple[int, str, bool]] = []
        self.failures: list[TelegramError] = []

    def send(self, chat_id: int, text: str, *, silent: bool = False) -> None:
        if self.failures:
            raise self.failures.pop(0)
        self.messages.append((chat_id, text, silent))

    @property
    def texts(self) -> list[str]:
        return [text for _, text, _ in self.messages]


@pytest.fixture
def conn(tmp_path: Path) -> Iterator[sqlite3.Connection]:
    with closing(storage.connect(tmp_path / "netwatch.db")) as c:
        yield c


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def tg() -> FakeTelegram:
    return FakeTelegram()


def _notifier(conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock) -> Notifier:
    return Notifier(
        conn, tg, 42, 30, "netwatch-test", wall_us=clock.wall, monotonic=clock.mono, tz=UTC
    )


def _started(conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock) -> Notifier:
    notifier = _notifier(conn, tg, clock)
    notifier.start(boot_us=T0 - 3600 * 1_000_000)
    clock.advance(1)
    return notifier


def _raise(
    conn: sqlite3.Connection,
    clock: Clock,
    kind: str = "ssh-brute-force",
    subject: str = "192.0.2.7",
    severity: str = SEVERITY_WARNING,
    message: str = "5 or more failed SSH logins from 192.0.2.7 within 10 minutes",
) -> int:
    with storage.transaction(conn):
        return alerts.add(conn, Alert(clock.wall(), kind, severity, subject, message))


def _notified(conn: sqlite3.Connection, alert_id: int) -> int | None:
    stored = alerts.get(conn, alert_id)
    assert stored is not None
    return stored.notified_us


def test_first_start_never_sends_the_alerts_raised_before_it(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    # Regression: the Netwatch VM held nine alerts from earlier demos with notified_us unset. A
    # notifier that sent every unsent row would have opened with nine week-old messages.
    old = [_raise(conn, clock, subject=f"192.0.2.{n}") for n in range(9)]
    clock.advance(60)
    notifier = _started(conn, tg, clock)
    assert notifier.poll() == 0
    assert tg.messages == []
    assert all(_notified(conn, alert_id) is None for alert_id in old)
    new = _raise(conn, clock)
    assert notifier.poll() == 1
    assert _notified(conn, new) == clock.wall()
    # A later start keeps the first baseline: the old alerts stay unsent.
    clock.advance(60)
    _notifier(conn, tg, clock).start(boot_us=T0 - 3600 * 1_000_000)
    assert storage.get_meta(conn, notify.BASELINE_KEY) == str(T0 + 60_000_000)


def test_an_alert_is_sent_once_with_its_details(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    _raise(conn, clock)
    assert notifier.poll() == 1
    assert notifier.poll() == 0
    chat_id, text, silent = tg.messages[0]
    assert chat_id == 42
    assert text.splitlines() == [
        "\U0001f7e1 WARNING: ssh-brute-force",
        "5 or more failed SSH logins from 192.0.2.7 within 10 minutes",
        "netwatch-test, 07:33:21 UTC",
    ]
    assert silent
    assert notify.counts(conn) == {"sent": 1, "suppressed": 0, "summarised": 0}


def test_critical_alerts_and_tests_make_the_phone_buzz(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    _raise(conn, clock, kind="ssh-login-after-failures", severity=SEVERITY_CRITICAL)
    _raise(conn, clock, kind=notify.KIND_TEST, subject="netwatch", message="hello")
    _raise(conn, clock, kind="new-device", subject="00:00:5e:00:53:01")
    notifier.poll()
    assert [silent for _, _, silent in tg.messages] == [False, False, True]
    assert tg.texts[0].startswith("\U0001f534 CRITICAL: ssh-login-after-failures")
    assert tg.texts[1].startswith("✅ TEST\nhello")


def test_an_alert_waits_while_telegram_is_unreachable_and_goes_out_after(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    alert_id = _raise(conn, clock)
    tg.failures = [TelegramError("cannot reach Telegram", temporary=True)] * 2
    assert notifier.poll() == 0
    assert _notified(conn, alert_id) is None
    # Backing off: no new attempt until 10 s have passed, then 20 s after the second failure.
    clock.advance(5)
    assert notifier.poll() == 0
    assert len(tg.failures) == 1
    clock.advance(5)
    assert notifier.poll() == 0
    clock.advance(19)
    assert notifier.poll() == 0
    clock.advance(1)
    assert notifier.poll() == 1
    assert _notified(conn, alert_id) is not None
    assert notify.telegram_errors(conn) == 2


def test_too_many_requests_waits_as_long_as_telegram_asks(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    _raise(conn, clock)
    tg.failures = [TelegramError("Too Many Requests", temporary=True, retry_after=42)]
    notifier.poll()
    clock.advance(41)
    assert notifier.poll() == 0
    clock.advance(1)
    assert notifier.poll() == 1


def test_a_wrong_token_or_chat_retries_slowly(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock, caplog: pytest.LogCaptureFixture
) -> None:
    notifier = _started(conn, tg, clock)
    _raise(conn, clock)
    tg.failures = [TelegramError("Telegram refused sendMessage: Unauthorized", temporary=False)]
    notifier.poll()
    assert "check the bot token" in caplog.text
    clock.advance(notify.BACKOFF_MAX_S - 1)
    assert notifier.poll() == 0
    clock.advance(1)
    assert notifier.poll() == 1


def test_repeats_within_the_cooldown_are_held_back(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    first = _raise(conn, clock)
    notifier.poll()
    clock.advance(10 * 60)
    repeat = _raise(conn, clock)
    other = _raise(conn, clock, subject="192.0.2.8", message="failed logins from 192.0.2.8")
    assert notifier.poll() == 1
    assert len(tg.messages) == 2
    assert "192.0.2.8" in tg.texts[1]
    assert _notified(conn, repeat) is not None  # dealt with, by holding it back
    # 30 minutes after the first message, the next repeat is sent again.
    clock.advance(20 * 60)
    _raise(conn, clock)
    assert notifier.poll() == 1
    assert notify.counts(conn) == {"sent": 3, "suppressed": 1, "summarised": 0}
    assert {first, other} <= {a.id for a in alerts.recent(conn, 10) if a.notified_us}


def test_a_repeat_is_not_held_back_when_the_first_one_failed(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    _raise(conn, clock)
    repeat = _raise(conn, clock)
    tg.failures = [TelegramError("cannot reach Telegram", temporary=True)]
    notifier.poll()
    assert _notified(conn, repeat) is None
    clock.advance(10)
    notifier.poll()
    assert len(tg.messages) == 1
    assert _notified(conn, repeat) is not None
    assert notify.counts(conn)["suppressed"] == 1


def test_the_cooldown_survives_a_restart_of_the_service(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    _started(conn, tg, clock)
    _raise(conn, clock)
    _notifier(conn, tg, clock).poll()
    clock.advance(60)
    _raise(conn, clock)
    assert _notifier(conn, tg, clock).poll() == 0
    assert len(tg.messages) == 1


def test_tests_and_restarts_are_never_held_back(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    for _ in range(2):
        _raise(conn, clock, kind=notify.KIND_TEST, subject="netwatch")
        _raise(conn, clock, kind=notify.KIND_RESTART, subject="netwatch-test")
    assert notifier.poll() == 4


def test_a_burst_goes_out_as_one_summary(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    for n in range(12):
        _raise(conn, clock, subject=f"192.0.2.{n}")
        clock.advance(1)
    _raise(conn, clock, kind="new-device", subject="00:00:5e:00:53:01")
    _raise(conn, clock, kind="ssh-login-after-failures", severity=SEVERITY_CRITICAL)
    assert notifier.poll() == 1
    _, text, silent = tg.messages[0]
    assert text.splitlines()[0] == (
        "\U0001f534 14 alerts at once: 12 ssh-brute-force, 1 new-device, 1 ssh-login-after-failures"
    )
    assert "Raised 07:33:21 UTC to 07:33:33 UTC" in text
    assert "netwatch alerts" in text
    assert not silent  # one of them is critical
    assert notify.counts(conn) == {"sent": 0, "suppressed": 0, "summarised": 14}
    assert notifier.poll() == 0


def test_no_more_than_ten_messages_a_minute(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    for n in range(10):
        _raise(conn, clock, subject=f"192.0.2.{n}")
        notifier.poll()
        clock.advance(1)
    late = _raise(conn, clock, subject="192.0.2.99")
    assert notifier.poll() == 0
    assert _notified(conn, late) is None
    clock.advance(51)
    assert notifier.poll() == 1
    assert len(tg.messages) == 11


def test_a_reboot_since_the_last_heartbeat_raises_a_restart_alert(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    notifier.heartbeat()
    beat = clock.wall()
    # The PC crashes 37 minutes later; the VM boots and the notifier starts 40 s after boot.
    clock.advance(37 * 60)
    boot = clock.wall()
    clock.advance(40)
    raised = _notifier(conn, tg, clock).start(boot_us=boot)
    assert raised is not None
    assert raised.kind == notify.KIND_RESTART
    assert raised.subject == "netwatch-test"
    assert raised.message == (
        "The host restarted: last heartbeat 07:33:21 UTC, booted 08:10:21 UTC, down for about"
        " 37 min. Nothing on it could alert in between."
    )
    assert beat < boot
    assert _notifier(conn, tg, clock).poll() == 1
    assert "WARNING: restart" in tg.texts[0]


def test_restarting_only_the_service_raises_nothing(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    boot = T0 - 3600 * 1_000_000
    assert _notifier(conn, tg, clock).start(boot_us=boot) is None  # the first start
    clock.advance(600)
    assert _notifier(conn, tg, clock).start(boot_us=boot) is None


def test_prune_removes_only_the_notifiers_own_old_alerts(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    notifier = _started(conn, tg, clock)
    _raise(conn, clock, kind=notify.KIND_TEST, subject="netwatch")
    _raise(conn, clock)
    clock.advance(notify.RETENTION_DAYS * 86_400 + 1)
    assert notifier.prune() == 1
    assert [a.kind for a in alerts.recent(conn, 10)] == ["ssh-brute-force"]


def test_status_reports_what_was_done_and_what_waits(
    conn: sqlite3.Connection, tg: FakeTelegram, clock: Clock
) -> None:
    settings = load_settings({"NETWATCH_TELEGRAM_CHAT_ID": "42"})
    assert notify.status(conn, settings).baseline_us is None
    notifier = _started(conn, tg, clock)
    _raise(conn, clock)
    notifier.poll()
    waiting = _raise(conn, clock, subject="192.0.2.8")
    found = notify.status(conn, settings)
    assert found.chat_id == 42
    assert found.counts["sent"] == 1
    assert found.unsent == 1
    stored = alerts.get(conn, waiting)
    assert stored is not None
    assert found.oldest_unsent_us == stored.ts_us


def test_formatting_shows_the_date_for_an_alert_from_another_day() -> None:
    stored = alerts.StoredAlert(1, T0, "new-device", SEVERITY_WARNING, "x", "a new device", None)
    text = notify.format_alert(stored, "netwatch", T0 + 86_400_000_000, UTC)
    assert text.endswith("netwatch, 26 Oct 07:33 UTC")


@pytest.mark.parametrize(
    ("seconds", "text"),
    [
        (20, "under a minute"),
        (37 * 60, "37 min"),
        (3600, "1 h"),
        (3725, "1 h 2 min"),
        (5 * 86_400, "5 days"),
    ],
)
def test_durations_read_naturally(seconds: float, text: str) -> None:
    assert notify._duration(seconds) == text


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="CLOCK_BOOTTIME is Linux-only")
def test_boot_time_is_in_the_past() -> None:
    assert 0 < notify.boot_time_us() < notify._wall_us()


# --- run() and send_test(), with a database on disk ---------------------------------------------


@pytest.fixture
def env(tmp_path: Path) -> dict[str, str]:
    return {"NETWATCH_STATE_DIR": str(tmp_path), "NETWATCH_TELEGRAM_CHAT_ID": "42"}


def test_run_needs_a_chat_id(tmp_path: Path) -> None:
    settings = load_settings({"NETWATCH_STATE_DIR": str(tmp_path)})
    with pytest.raises(ConfigError, match="NETWATCH_TELEGRAM_CHAT_ID"):
        notify.run(settings, threading.Event(), {}, sender=FakeTelegram())


def test_run_sends_what_is_waiting_and_stops(env: dict[str, str], tmp_path: Path) -> None:
    settings = load_settings(env)
    tg = FakeTelegram()
    stop = threading.Event()
    stop.set()
    # A first run records the baseline; an alert raised after it is sent by the next run.
    assert notify.run(settings, stop, {}, sender=tg, boot_us=0) == 0
    now = Clock()
    now.us = notify._wall_us()
    with closing(storage.connect(tmp_path / "netwatch.db")) as conn:
        _raise(conn, now)
    assert notify.run(settings, stop, {}, sender=tg, boot_us=0) == 0
    assert len(tg.messages) == 1


def test_send_test_returns_once_the_service_has_sent_it(
    env: dict[str, str], tmp_path: Path
) -> None:
    settings = load_settings(env)
    tg = FakeTelegram()
    clock = Clock()
    with closing(storage.connect(tmp_path / "netwatch.db")) as conn:
        service = _notifier(conn, tg, clock)
        service.start(boot_us=0)
        clock.advance(1)
        # The command waits one second at a time; here the "service" polls in that second.
        sent = notify.send_test(
            settings,
            "hello",
            wall_us=clock.wall,
            monotonic=clock.mono,
            sleep=lambda _: service.poll(),
        )
    assert sent.kind == notify.KIND_TEST
    assert sent.notified_us is not None
    assert tg.texts == [
        f"✅ TEST\nhello\nnetwatch-test, {notify._clock(sent.ts_us, sent.ts_us, UTC)}"
    ]


def test_send_test_says_when_the_service_does_not_send_it(
    env: dict[str, str], tmp_path: Path
) -> None:
    settings = load_settings(env)
    clock = Clock()
    with closing(storage.connect(tmp_path / "netwatch.db")) as conn:
        _notifier(conn, FakeTelegram(), clock).start(boot_us=0)

    def sleep(seconds: float) -> None:
        clock.advance(seconds)

    with pytest.raises(NetwatchError, match=r"is queued, but netwatch-notify did not send it"):
        notify.send_test(settings, "hello", wall_us=clock.wall, monotonic=clock.mono, sleep=sleep)


def test_send_test_before_the_service_ever_ran(env: dict[str, str], tmp_path: Path) -> None:
    storage.connect(tmp_path / "netwatch.db").close()
    with pytest.raises(NetwatchError, match="has never run on this host"):
        notify.send_test(load_settings(env))
