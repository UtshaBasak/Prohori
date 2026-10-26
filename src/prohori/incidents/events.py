"""What the incident builder remembers about events: a slim, bounded copy of each one.

Alerts only carry event ids. The builder needs the events behind them for linking, the timeline
and the scoring checks, so :class:`EventContext` watches the events on their way into the rule
engine and keeps a small summary of each (never the raw line), up to a fixed number.
"""

from collections import OrderedDict
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime

from prohori.incidents.novelty import SignInHistory
from prohori.schema import Event

#: Event summaries kept in memory by default; older ones are dropped first (and counted).
MAX_EVENTS = 100_000

#: Fields that link alerts into one incident: they identify an attacker or a victim.
#: ``host`` and ``log_source`` are left out on purpose: every line of one server's log shares
#: them, so linking on them would merge everything.
LINK_FIELDS = (
    "source.ip",
    "user.id",
    "user.name",
    "user.email_hash",
    "request_id",
    "extra.session_id",
)

#: Link fields that name an account (used to detect shared IP addresses).
USER_FIELDS = frozenset({"user.id", "user.name", "user.email_hash"})


@dataclass(frozen=True, slots=True)
class EventSummary:
    """The parts of an event the incident builder uses."""

    id: str
    timestamp: datetime
    log_source: str
    action: str
    category: str
    outcome: str
    source_ip: str | None = None
    user_id: str | None = None
    user_name: str | None = None
    email_hash: str | None = None
    request_id: str | None = None
    session_id: str | None = None
    client: str | None = None
    user_agent: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    http_status: int | None = None

    @classmethod
    def from_event(cls, event: Event) -> "EventSummary":
        session = event.extra.get("session_id")
        return cls(
            id=event.id,
            timestamp=event.timestamp,
            log_source=event.log_source,
            action=event.event.action,
            category=event.event.category.value,
            outcome=event.event.outcome.value,
            source_ip=str(event.source.ip) if event.source.ip is not None else None,
            user_id=event.user.id,
            user_name=event.user.name,
            email_hash=event.user.email_hash,
            request_id=event.request_id,
            session_id=str(session) if session is not None else None,
            client=event.client,
            user_agent=event.user_agent,
            http_method=event.http.method,
            http_path=event.http.path,
            http_status=event.http.status,
        )

    def link_value(self, field: str) -> str | None:
        """Return the value of one of :data:`LINK_FIELDS`."""
        return {
            "source.ip": self.source_ip,
            "user.id": self.user_id,
            "user.name": self.user_name,
            "user.email_hash": self.email_hash,
            "request_id": self.request_id,
            "extra.session_id": self.session_id,
        }[field]

    @property
    def account(self) -> str | None:
        """The account the event concerns: the user id, else the user name."""
        return self.user_id or self.user_name


class EventContext:
    """Bounded memory of the events seen in one run, plus the sign-in history of each account.

    Wrap the event stream with :meth:`observe` before it goes into the rule engine.
    """

    def __init__(
        self, *, max_events: int = MAX_EVENTS, history: SignInHistory | None = None
    ) -> None:
        if max_events < 1:
            msg = "max_events must be at least 1"
            raise ValueError(msg)
        self.max_events = max_events
        self.history = history if history is not None else SignInHistory()
        self.dropped = 0
        self._events: OrderedDict[str, EventSummary] = OrderedDict()

    def add(self, event: Event) -> None:
        summary = EventSummary.from_event(event)
        self.history.add(summary)
        if summary.id in self._events:
            return
        self._events[summary.id] = summary
        if len(self._events) > self.max_events:
            self._events.popitem(last=False)
            self.dropped += 1

    def observe(self, events: Iterable[Event]) -> Iterator[Event]:
        """Pass ``events`` through unchanged, remembering each one."""
        for event in events:
            self.add(event)
            yield event

    def get(self, event_id: str) -> EventSummary | None:
        return self._events.get(event_id)

    def __len__(self) -> int:
        return len(self._events)
