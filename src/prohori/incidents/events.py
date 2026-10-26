"""What the incident builder remembers about events: a slim, bounded copy of each one.

Alerts only carry event ids. The builder needs the events behind them for linking, the timeline
and the scoring checks, so :class:`EventContext` watches the events on their way into the rule
engine and keeps a small summary of each (never the raw line), up to a fixed number.
"""

from collections import OrderedDict
from collections.abc import Iterable, Iterator

from prohori.incidents.novelty import SignInHistory
from prohori.incidents.summary import EventSummary
from prohori.schema import Event

#: Event summaries kept in memory by default; older ones are dropped first (and counted).
MAX_EVENTS = 100_000


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
