from __future__ import annotations

from netwatch.authlog import (
    KIND_BRUTE_FORCE,
    KIND_LOGIN_AFTER_FAILURES,
    SEVERITY_CRITICAL,
    SEVERITY_WARNING,
    AuthMonitor,
)
from netwatch.journal import Record

MINUTE_US = 60_000_000
ATTACKER = "203.0.113.5"


def _failure(ts_us: int, port: int, source: str = ATTACKER) -> Record:
    # What OpenSSH 10.2 logs for a failed attempt on a server without password logins.
    message = f"Connection reset by authenticating user root {source} port {port} [preauth]"
    return Record(message, ts_us, f"cursor-{ts_us}-{port}")


def _login(ts_us: int, source: str = ATTACKER) -> Record:
    message = f"Accepted publickey for alice from {source} port 50000 ssh2: ED25519 SHA256:abcdef"
    return Record(message, ts_us, f"cursor-{ts_us}-login")


def _feed(monitor: AuthMonitor, records: list[Record]) -> list:
    alerts = []
    for record in records:
        alerts += monitor.feed(record)[1]
    return alerts


def test_events_carry_what_sshd_logged() -> None:
    monitor = AuthMonitor(max_failures=5, window_minutes=10)
    event, alerts = monitor.feed(Record("Invalid user nwtest from 203.0.113.5 port 63998", 1, "c1"))
    assert (event, alerts) == (None, [])  # not an attempt by itself; the next line counts it
    event, _ = monitor.feed(
        Record("Connection reset by invalid user nwtest 203.0.113.5 port 63998 [preauth]", 2, "c2")
    )
    assert event is not None
    assert (event.source, event.username, event.outcome, event.invalid_user, event.cursor) == (
        ATTACKER,
        "nwtest",
        "failed",
        True,
        "c2",
    )
    event, _ = monitor.feed(_login(3))
    assert (event.outcome, event.method, event.invalid_user) == ("accepted", "publickey", False)


def test_unrelated_sshd_lines_are_ignored() -> None:
    monitor = AuthMonitor(max_failures=5, window_minutes=10)
    for message in (
        "Server listening on 0.0.0.0 port 22.",
        "Received disconnect from 192.0.2.10 port 51122:11: disconnected by user",
        "pam_unix(sshd:session): session opened for user alice(uid=1000) by alice(uid=0)",
    ):
        assert monitor.feed(Record(message, 1, "c")) == (None, [])


def test_brute_force_alert_at_the_threshold_once_per_window() -> None:
    monitor = AuthMonitor(max_failures=5, window_minutes=10)
    alerts = _feed(monitor, [_failure(i * 1_000_000, 4000 + i) for i in range(4)])
    assert alerts == []
    [alert] = _feed(monitor, [_failure(5_000_000, 4005)])
    assert (alert.kind, alert.severity, alert.subject) == (
        KIND_BRUTE_FORCE,
        SEVERITY_WARNING,
        ATTACKER,
    )
    assert alert.message.startswith("5 or more failed SSH logins from 203.0.113.5 within 10 min")
    # The attack goes on: no new alert while the last one is less than a window old ...
    assert _feed(monitor, [_failure(6_000_000 + i, 5000 + i) for i in range(20)]) == []
    # ... and a new one once it is older and the address is still over the limit.
    later = 5_000_000 + 10 * MINUTE_US + 1
    burst = [_failure(later + i, 6000 + i) for i in range(5)]
    assert [a.kind for a in _feed(monitor, burst)] == [KIND_BRUTE_FORCE]


def test_failures_spread_beyond_the_window_raise_nothing() -> None:
    monitor = AuthMonitor(max_failures=5, window_minutes=10)
    records = [_failure(i * 3 * MINUTE_US, 4000 + i) for i in range(10)]  # one every 3 minutes
    assert _feed(monitor, records) == []


def test_addresses_are_counted_separately() -> None:
    monitor = AuthMonitor(max_failures=3, window_minutes=10)
    records = [_failure(i, 4000 + i, source=f"198.51.100.{i % 3}") for i in range(6)]
    assert _feed(monitor, records) == []


def test_login_after_a_brute_force_alert_is_critical() -> None:
    monitor = AuthMonitor(max_failures=3, window_minutes=10)
    alerts = _feed(monitor, [_failure(i, 4000 + i) for i in range(3)] + [_login(100)])
    assert [(a.kind, a.severity) for a in alerts] == [
        (KIND_BRUTE_FORCE, SEVERITY_WARNING),
        (KIND_LOGIN_AFTER_FAILURES, SEVERITY_CRITICAL),
    ]
    assert alerts[1].message.startswith("successful SSH login as 'alice' from 203.0.113.5")


def test_ordinary_logins_raise_nothing() -> None:
    monitor = AuthMonitor(max_failures=3, window_minutes=10)
    # Two typos then a login is normal; so is a login long after an old alert.
    assert _feed(monitor, [_failure(1, 4001), _failure(2, 4002), _login(3)]) == []
    monitor = AuthMonitor(max_failures=3, window_minutes=10)
    _feed(monitor, [_failure(i, 4000 + i) for i in range(3)])
    assert _feed(monitor, [_login(11 * MINUTE_US)]) == []


def test_a_username_cannot_frame_another_address() -> None:
    # Regression guard for the log-analyzer 0.6.0 fix this relies on.
    monitor = AuthMonitor(max_failures=5, window_minutes=10)
    event, _ = monitor.feed(
        Record("Connection closed by invalid user 192.0.2.1 203.0.113.5 port 7 [preauth]", 1, "c")
    )
    assert event is not None and event.source == ATTACKER


def test_restore_continues_the_window_across_a_restart() -> None:
    monitor = AuthMonitor(max_failures=5, window_minutes=10)
    monitor.restore(failures=[(ATTACKER, i) for i in range(4)], alerts=[])
    [alert] = _feed(monitor, [_failure(10, 4010)])
    assert alert.kind == KIND_BRUTE_FORCE

    # An alert raised before the restart keeps its cooldown and its login check.
    monitor = AuthMonitor(max_failures=2, window_minutes=10)
    monitor.restore(failures=[], alerts=[(ATTACKER, 5)])
    assert _feed(monitor, [_failure(10, 4010), _failure(11, 4011)]) == []
    assert [a.kind for a in _feed(monitor, [_login(12)])] == [KIND_LOGIN_AFTER_FAILURES]


def test_one_login_alert_per_brute_force_alert() -> None:
    # Regression, found on the VM: every later login from the address raised another critical
    # alert (three in 25 seconds), which Phase 4 would have sent as three Telegram messages.
    monitor = AuthMonitor(max_failures=3, window_minutes=10)
    _feed(monitor, [_failure(i, 4000 + i) for i in range(3)])
    alerts = _feed(monitor, [_login(10), _login(20), _login(30)])
    assert [a.kind for a in alerts] == [KIND_LOGIN_AFTER_FAILURES]
    # A new brute-force alert (after the cooldown) re-arms the check.
    later = 11 * MINUTE_US
    alerts = _feed(monitor, [_failure(later + i, 5000 + i) for i in range(3)] + [_login(later + 9)])
    assert [a.kind for a in alerts] == [KIND_BRUTE_FORCE, KIND_LOGIN_AFTER_FAILURES]


def test_restore_remembers_that_the_login_was_reported() -> None:
    monitor = AuthMonitor(max_failures=2, window_minutes=10)
    monitor.restore(failures=[], alerts=[(ATTACKER, 5)], login_alerts=[(ATTACKER, 7)])
    assert _feed(monitor, [_login(12)]) == []
