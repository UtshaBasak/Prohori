"""Behaviour features per source IP and time window, from normalised events.

Each event with a source address is put in a tumbling window (five minutes by default) of its
source IP. A window's features describe what that address did in it: how many sign-in attempts
and how many failed, how many accounts and paths it touched, how its HTTP requests ended, how
varied its paths and user agents were, how many of its account and client pairs were new, and
how much of it happened at night.

Standard library only, so the anomaly baselines work without the ``ml`` extra. Ratios are
computed only for windows with at least :data:`MIN_RATIO_EVENTS` events of the kind they divide
by and are 0 otherwise: one failed sign-in is not a failure ratio of 100 %.
"""

import math
from collections import Counter
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

from prohori.schema import Event
from prohori.schema.types import EventCategory, Outcome

WINDOW = timedelta(minutes=5)
#: Fewest events of a kind before a ratio over them is computed.
MIN_RATIO_EVENTS = 5
#: Event ids kept per window, as many as a rule alert lists.
MAX_WINDOW_EVENT_IDS = 100
#: Local hours counted as night: from 22:00 to 06:59.
NIGHT_HOURS = frozenset({22, 23, 0, 1, 2, 3, 4, 5, 6})

FEATURES = (
    "events",
    "rate_per_minute",
    "auth_attempts",
    "auth_failures",
    "failure_ratio",
    "distinct_users",
    "http_requests",
    "distinct_paths",
    "http_4xx_ratio",
    "path_entropy",
    "distinct_user_agents",
    "new_client_ratio",
    "night_ratio",
)


@dataclass
class Window:
    """One source IP's activity in one window, and its features."""

    ip: str
    start: datetime
    first_seen: datetime
    last_seen: datetime
    event_ids: tuple[str, ...]
    features: dict[str, float]


@dataclass
class _Activity:
    first_seen: datetime
    last_seen: datetime
    event_ids: list[str] = field(default_factory=list)
    events: int = 0
    auth: int = 0
    failures: int = 0
    users: set[str] = field(default_factory=set)
    http: int = 0
    http_4xx: int = 0
    paths: Counter[str] = field(default_factory=Counter)
    user_agents: set[str] = field(default_factory=set)
    client_events: int = 0
    new_clients: int = 0
    night: int = 0


def _user(event: Event) -> str | None:
    return event.user.id or event.user.name or event.user.email_hash


def entropy(counts: Iterable[int]) -> float:
    """Shannon entropy in bits of a distribution given by its counts."""
    values = [c for c in counts if c > 0]
    total = sum(values)
    if total == 0:
        return 0.0
    return -sum(c / total * math.log2(c / total) for c in values)


class FeatureExtractor:
    """Collects events and computes the features of every (source IP, window).

    ``timezone`` is the zone whose local hours decide what counts as night. Events must arrive
    roughly in time order for the new-client feature to mean "not seen earlier in this log".
    """

    def __init__(self, *, window: timedelta = WINDOW, timezone: str = "UTC") -> None:
        if window <= timedelta(0):
            msg = "window must be positive"
            raise ValueError(msg)
        self.window = window
        self.zone = ZoneInfo(timezone)
        self._activity: dict[tuple[str, datetime], _Activity] = {}
        self._clients: set[tuple[str, str]] = set()
        self.skipped = 0  # events without a source address

    def _start(self, timestamp: datetime) -> datetime:
        seconds = self.window.total_seconds()
        epoch = timestamp.timestamp()
        return datetime.fromtimestamp(epoch - epoch % seconds, tz=UTC)

    def observe(self, event: Event) -> None:
        if event.source.ip is None:
            self.skipped += 1
            return
        ip = str(event.source.ip)
        key = (ip, self._start(event.timestamp))
        activity = self._activity.get(key)
        if activity is None:
            activity = self._activity[key] = _Activity(event.timestamp, event.timestamp)
        activity.first_seen = min(activity.first_seen, event.timestamp)
        activity.last_seen = max(activity.last_seen, event.timestamp)
        if len(activity.event_ids) < MAX_WINDOW_EVENT_IDS:
            activity.event_ids.append(event.id)
        activity.events += 1
        category = event.event.category
        if category is EventCategory.AUTHENTICATION:
            activity.auth += 1
            activity.failures += event.event.outcome is Outcome.FAILURE
        user = _user(event)
        if user is not None:
            activity.users.add(user)
        if event.http.status is not None:
            activity.http += 1
            activity.http_4xx += 400 <= event.http.status < 500
        if event.http.path is not None:
            activity.paths[event.http.path] += 1
        if event.user_agent:
            activity.user_agents.add(event.user_agent)
        client = event.client or event.user_agent
        if user is not None and client:
            activity.client_events += 1
            if (user, client) not in self._clients:
                self._clients.add((user, client))
                activity.new_clients += 1
        if event.timestamp.astimezone(self.zone).hour in NIGHT_HOURS:
            activity.night += 1

    def observe_all(self, events: Iterable[Event]) -> Iterator[Event]:
        """Pass ``events`` through unchanged while observing them (to share one parse)."""
        for event in events:
            self.observe(event)
            yield event

    def windows(self) -> list[Window]:
        """Every (source IP, window) seen so far, in time order."""
        minutes = self.window.total_seconds() / 60
        found = []
        for (ip, start), a in sorted(
            self._activity.items(), key=lambda item: (item[0][1], item[0][0])
        ):
            features = {
                "events": float(a.events),
                "rate_per_minute": a.events / minutes,
                "auth_attempts": float(a.auth),
                "auth_failures": float(a.failures),
                "failure_ratio": a.failures / a.auth if a.auth >= MIN_RATIO_EVENTS else 0.0,
                "distinct_users": float(len(a.users)),
                "http_requests": float(a.http),
                "distinct_paths": float(len(a.paths)),
                "http_4xx_ratio": a.http_4xx / a.http if a.http >= MIN_RATIO_EVENTS else 0.0,
                "path_entropy": entropy(a.paths.values()) if a.http >= MIN_RATIO_EVENTS else 0.0,
                "distinct_user_agents": float(len(a.user_agents)),
                "new_client_ratio": (
                    a.new_clients / a.client_events if a.client_events >= MIN_RATIO_EVENTS else 0.0
                ),
                "night_ratio": a.night / a.events if a.events >= MIN_RATIO_EVENTS else 0.0,
            }
            found.append(Window(ip, start, a.first_seen, a.last_seen, tuple(a.event_ids), features))
        return found


def extract(
    events: Iterable[Event], *, window: timedelta = WINDOW, timezone: str = "UTC"
) -> list[Window]:
    """The windows of ``events`` (see :class:`FeatureExtractor`)."""
    extractor = FeatureExtractor(window=window, timezone=timezone)
    for event in events:
        extractor.observe(event)
    return extractor.windows()
