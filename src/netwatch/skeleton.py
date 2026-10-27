"""Phase 0 walking skeleton: a service that proves the deploy pipeline before any features exist.

Installed by deploy/install.sh as netwatch-skeleton.service, it exercises everything the real
services will rely on: it runs as the unprivileged netwatch user under the hardened unit, writes
to its state directory through the storage layer, logs its version and git revision to the
journal, and stops cleanly on SIGTERM. Phase 1 replaces it with the DNS service.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from contextlib import closing
from datetime import UTC, datetime

from netwatch import __version__, storage
from netwatch.config import Settings
from netwatch.errors import StorageError

DB_NAME = "netwatch.db"

log = logging.getLogger("netwatch.skeleton")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def run(
    settings: Settings,
    stop: threading.Event,
    clock: Callable[[], datetime] = _utc_now,
) -> int:
    """Record the start in the database, then idle until ``stop`` is set. Returns the exit code."""
    try:
        settings.state_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise StorageError(
            f"cannot create state directory {settings.state_dir}: {exc.strerror}"
        ) from exc

    db_path = settings.state_dir / DB_NAME
    revision = settings.revision or "unknown"
    with closing(storage.connect(db_path)) as conn:
        storage.set_meta(conn, "skeleton.last_start", clock().isoformat(timespec="seconds"))
        storage.set_meta(conn, "skeleton.revision", revision)
    log.info("started version=%s revision=%s db=%s", __version__, revision, db_path)

    # Wake up every second rather than blocking forever, so a stop request is noticed promptly
    # on every platform, including ones where a signal can't interrupt a lock wait.
    while not stop.wait(timeout=1.0):
        pass
    log.info("stopped")
    return 0
