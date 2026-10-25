"""Persistent SQLite cache for enrichment results and daily request counts.

Only successful lookups and "no data" answers are cached; failures never are, so a transient
error cannot stick for a whole TTL. Values are stored as JSON (never pickle). Each operation opens
and closes its own connection, so no file handle stays open between calls.
"""

import json
import os
import sqlite3
import sys
from collections.abc import Callable, Iterator
from contextlib import closing, contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from prohori.enrich.provider import ProviderData

Clock = Callable[[], datetime]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS lookups (
    provider TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT,
    retrieved_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (provider, key)
);
CREATE TABLE IF NOT EXISTS usage (
    provider TEXT NOT NULL,
    day TEXT NOT NULL,
    requests INTEGER NOT NULL,
    PRIMARY KEY (provider, day)
);
"""


def utc_now() -> datetime:
    """Return the current time in UTC (the default clock)."""
    return datetime.now(UTC)


def default_cache_path() -> Path:
    """Return the per-user cache file: ``%LOCALAPPDATA%`` on Windows, ``$XDG_CACHE_HOME`` else."""
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache")
    return base / "prohori" / "enrich.sqlite3"


@dataclass(frozen=True)
class CachedLookup:
    """A cached answer. ``data`` is ``None`` when the provider had nothing for the address."""

    data: ProviderData | None
    retrieved_at: datetime


class EnrichmentCache:
    """Cache of provider answers keyed by provider and normalised indicator, with expiry."""

    def __init__(self, path: Path, *, clock: Clock = utc_now) -> None:
        self.path = path
        self._clock = clock
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with closing(sqlite3.connect(self.path, timeout=5)) as db, db:
            yield db

    def get(self, provider: str, key: str) -> CachedLookup | None:
        """Return the unexpired cached answer, or ``None`` on a miss."""
        now = self._clock().isoformat()
        with self._connect() as db:
            row = db.execute(
                "SELECT value, retrieved_at FROM lookups"
                " WHERE provider = ? AND key = ? AND expires_at > ?",
                (provider, key, now),
            ).fetchone()
        if row is None:
            return None
        try:
            data = None if row[0] is None else json.loads(row[0])
        except json.JSONDecodeError:
            return None  # a corrupted entry is a miss; the next success overwrites it
        if data is not None and not isinstance(data, dict):
            return None
        return CachedLookup(data, datetime.fromisoformat(row[1]))

    def put(self, provider: str, key: str, data: ProviderData | None, ttl: timedelta) -> datetime:
        """Store an answer for ``ttl`` and return its retrieval time."""
        now = self._clock()
        value = None if data is None else json.dumps(data, sort_keys=True)
        with self._connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO lookups VALUES (?, ?, ?, ?, ?)",
                (provider, key, value, now.isoformat(), (now + ttl).isoformat()),
            )
        return now

    def purge_expired(self) -> int:
        """Delete expired entries and return how many were removed."""
        now = self._clock().isoformat()
        with self._connect() as db:
            return db.execute("DELETE FROM lookups WHERE expires_at <= ?", (now,)).rowcount

    def requests_today(self, provider: str) -> int:
        """Return how many requests were sent to ``provider`` today (UTC)."""
        with self._connect() as db:
            row = db.execute(
                "SELECT requests FROM usage WHERE provider = ? AND day = ?",
                (provider, self._day()),
            ).fetchone()
        return int(row[0]) if row else 0

    def count_request(self, provider: str) -> int:
        """Record one request sent to ``provider`` today and return the new total."""
        day = self._day()
        with self._connect() as db:
            db.execute(
                "INSERT INTO usage VALUES (?, ?, 1)"
                " ON CONFLICT (provider, day) DO UPDATE SET requests = requests + 1",
                (provider, day),
            )
            row = db.execute(
                "SELECT requests FROM usage WHERE provider = ? AND day = ?", (provider, day)
            ).fetchone()
        return int(row[0])

    def _day(self) -> str:
        return self._clock().astimezone(UTC).date().isoformat()
