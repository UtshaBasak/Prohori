"""The consumers: normalise -> detect -> build incidents, plus the shared stage loop.

Each stage reads its input topics in batches, publishes what the batch produced, flushes the
transport and then commits, so a crash replays the uncommitted batch (at-least-once). Anything a
stage cannot use (a line no parser accepts, a message that is not valid JSON or does not match its
schema) goes to the ``dead-letter`` topic with the reason and is counted; it is never retried, so
one bad message cannot stall the pipeline.

The detector and the incident stage keep state in memory (the rule engine's windows, the events
behind open incidents) and do not checkpoint it. They are marked ``stateful`` and read their
inputs from the start when the pipeline starts, so a restart rebuilds the same state and produces
the same alerts and incidents, with the same ids; the sink stores each id once.
"""

import json
import logging
import time
from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ValidationError

from prohori.enrich import Enricher
from prohori.incidents import EventContext, IncidentBuilder, IncidentSettings
from prohori.incidents.grouping import group_alerts
from prohori.incidents.provenance import with_provenance
from prohori.parsers import LineParser, ParseError, ParseStats, RawLine, get_parser
from prohori.pipeline.messages import DeadLetter, RawLog, Topic, dead_letter
from prohori.pipeline.transport import Record, Transport
from prohori.rules import CompiledRule, RuleEngine
from prohori.schema import Alert, Event

logger = logging.getLogger(__name__)

#: Event ids the detector remembers to drop duplicates (as many as the incident context keeps).
MAX_SEEN_EVENTS = 100_000
#: Alert ids the incident stage remembers after their incident was published.
MAX_DONE_ALERTS = 100_000


@dataclass
class StageMetrics:
    """Counters for one stage."""

    consumed: int = 0
    produced: int = 0
    dead_letters: int = 0
    duplicates: int = 0
    extra: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, int]:
        return {
            "consumed": self.consumed,
            "produced": self.produced,
            "dead_letters": self.dead_letters,
            "duplicates": self.duplicates,
            **self.extra,
        }


class Stage(ABC):
    """A consumer group that reads ``inputs``, handles each message and commits.

    Subclasses implement :meth:`handle` and may override :meth:`finish` (end of input or
    shutdown: release held state), :meth:`tick` (called after every batch) and :meth:`idle`
    (called when the input has been quiet for a while).
    """

    name: ClassVar[str]
    inputs: ClassVar[tuple[Topic, ...]]
    #: Rebuild in-memory state by reading the inputs from the start when the pipeline starts.
    stateful: ClassVar[bool] = False

    def __init__(self, transport: Transport) -> None:
        self.transport = transport
        self.metrics = StageMetrics()
        #: Called after every batch (the stack's heartbeat), so a long rebuild looks alive.
        self.progress: Callable[[], None] | None = None

    @property
    def group(self) -> str:
        return self.name

    def start(self) -> None:
        """Prepare to run: a stateful stage rewinds its inputs."""
        if self.stateful:
            for topic in self.inputs:
                self.transport.rewind(topic, self.group)

    def step(self, max_records: int) -> int:
        """Process at most ``max_records`` messages per input; return how many were read."""
        batches = [(t, self.transport.poll(t, self.group, max_records)) for t in self.inputs]
        return self._process(batches)

    def _process(self, batches: Sequence[tuple[Topic, list[Record]]]) -> int:
        count = 0
        for _topic, records in batches:
            for record in records:
                self.metrics.consumed += 1
                self._deliver(record)
            count += len(records)
        self.tick()
        self.transport.flush()
        for _topic, records in batches:
            if records:
                self.transport.commit(records[-1], self.group)
        if self.progress is not None:
            self.progress()
        return count

    def _deliver(self, record: Record) -> None:
        if record.value is None:
            self.reject(record, record.error or "unreadable message", record.raw)
            return
        try:
            self.handle(record.topic, record.value)
        except ValidationError as exc:
            first = exc.errors()[0] if exc.errors() else None
            where = ".".join(str(p) for p in first["loc"]) if first else "message"
            reason = f"invalid {where}: {first['msg']}" if first else "invalid message"
            self.reject(record, reason, _dump(record.value))
        except Exception as exc:  # one bad message must not stop the pipeline
            logger.exception("%s could not process a %s message", self.name, record.topic)
            self.reject(record, f"processing failed: {type(exc).__name__}", _dump(record.value))

    def reject(self, record: Record, reason: str, payload: str) -> None:
        """Send ``record`` to the dead-letter topic."""
        self.publish_dead_letter(dead_letter(self.name, record.topic, record.key, reason, payload))

    def publish_dead_letter(self, letter: DeadLetter) -> None:
        self.metrics.dead_letters += 1
        self.transport.publish(Topic.DEAD_LETTER, letter.id, letter.model_dump(mode="json"))

    def publish(self, topic: Topic, key: str, model: BaseModel) -> None:
        self.metrics.produced += 1
        self.transport.publish(topic, key, model.model_dump(mode="json"))

    @abstractmethod
    def handle(self, topic: Topic, value: Mapping[str, Any]) -> None:
        """Process one message (validation errors are turned into dead letters by the caller)."""

    def tick(self) -> None:  # noqa: B027 - optional hook, intentionally empty
        """Called after every batch, before the transport is flushed."""

    def idle(self) -> None:  # noqa: B027 - optional hook, intentionally empty
        """The inputs have been quiet for a while (live mode only)."""

    def finish(self) -> None:
        """End of input or shutdown: publish whatever is still held."""
        self.transport.flush()


def _dump(value: Mapping[str, Any]) -> str:
    return json.dumps(value, separators=(",", ":"))


# ---------------------------------------------------------------------- normaliser


@dataclass(frozen=True)
class ParserSettings:
    """Parser options for the whole run, as on the command line."""

    year: int | None = None
    timezone: str = "UTC"
    mapping: Path | None = None
    pattern: str | None = None
    keep_query: bool = False

    def create(self, name: str, read_at: datetime) -> LineParser:
        if name == "auth_log":
            return get_parser(name, year=self.year, timezone=self.timezone, reference_time=read_at)
        if name == "access_log":
            return get_parser(name, pattern=self.pattern, keep_query=self.keep_query)
        if name == "generic_json":
            if self.mapping is None:
                msg = "the generic_json parser needs a mapping file"
                raise ValueError(msg)
            return get_parser(name, mapping=self.mapping)
        return get_parser(name)


class Normaliser(Stage):
    """``raw-logs`` -> ``events``: parse each line with one long-lived parser per source.

    One parser per source keeps parser state (such as the year of ``auth.log`` timestamps) across
    messages. Malformed lines become dead letters; blank and irrelevant lines are counted.
    """

    name = "normalise"
    inputs = (Topic.RAW_LOGS,)

    def __init__(self, transport: Transport, settings: ParserSettings | None = None) -> None:
        super().__init__(transport)
        self.settings = settings or ParserSettings()
        self.parsers: dict[tuple[str, str], LineParser] = {}
        self.stats: dict[str, ParseStats] = {}

    def handle(self, topic: Topic, value: Mapping[str, Any]) -> None:
        raw = RawLog.model_validate(value)
        key = (raw.source, raw.parser)
        parser = self.parsers.get(key)
        if parser is None:
            parser = self.settings.create(raw.parser, raw.read_at)
            self.parsers[key] = parser
        stats = self.stats.setdefault(raw.source, ParseStats())
        line = RawLine(raw.line, raw.text, raw.too_long, raw.decode_error)
        try:
            event = parser.parse_raw(line, source=raw.source, stats=stats)
        except ParseError as exc:
            self.publish_dead_letter(
                dead_letter(self.name, topic, f"{raw.source}:{raw.line}", str(exc), raw.text)
            )
            return
        if event is not None:
            self.publish(Topic.EVENTS, event.id, event)

    def parse_counts(self) -> dict[str, int]:
        """Parse counters summed over all sources."""
        totals: dict[str, int] = {}
        for stats in self.stats.values():
            for name, value in stats.as_dict().items():
                if isinstance(value, int):
                    totals[name] = totals.get(name, 0) + value
        return totals


# ---------------------------------------------------------------------- detector


class _Seen:
    """A bounded set of ids, forgetting the oldest first."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self._ids: OrderedDict[str, None] = OrderedDict()

    def add(self, item: str) -> bool:
        """Remember ``item``; return False if it was already there."""
        if item in self._ids:
            return False
        self._ids[item] = None
        if len(self._ids) > self.limit:
            self._ids.popitem(last=False)
        return True

    def __contains__(self, item: str) -> bool:
        return item in self._ids


class Detector(Stage):
    """``events`` -> ``alerts``: the rule engine over the event stream.

    Events seen before (a replay, or a redelivery) are dropped before they reach the engine, so
    they cannot be counted twice by a threshold rule. With ``live`` (following live logs), events
    timestamped more than a day after ``now()`` are rejected, and "now" moves on before every
    batch, so a stage that runs for days keeps evaluating new events.
    """

    name = "detect"
    inputs = (Topic.EVENTS,)
    stateful = True

    def __init__(
        self,
        transport: Transport,
        rules: Sequence[CompiledRule],
        *,
        lateness: timedelta,
        live: bool = False,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        super().__init__(transport)
        self.rules = list(rules)
        self.lateness = lateness
        self.live = live
        self.now = now
        self.engine = self._engine()
        self.seen = _Seen(MAX_SEEN_EVENTS)

    def _engine(self) -> RuleEngine:
        reference = self.now() if self.live else None
        return RuleEngine(self.rules, lateness=self.lateness, reference_time=reference)

    def start(self) -> None:
        super().start()
        self.engine = self._engine()
        self.seen = _Seen(MAX_SEEN_EVENTS)

    def step(self, max_records: int) -> int:
        if self.live:
            self.engine.set_reference_time(self.now())
        late = self.engine.stats.late_events
        count = super().step(max_records)
        if self.engine.stats.late_events > late:
            logger.warning(
                "%d event(s) arrived too late for the rules and were not evaluated (older than "
                "events already processed); replay older logs first or start with fresh topics",
                self.engine.stats.late_events - late,
            )
        return count

    def handle(self, topic: Topic, value: Mapping[str, Any]) -> None:
        event = Event.model_validate(value)
        if not self.seen.add(event.id):
            self.metrics.duplicates += 1
            return
        self._emit(self.engine.process(event))

    def idle(self) -> None:
        """Release the events held for reordering, so a quiet log's last alerts are not held."""
        self._emit(self.engine.flush())
        self.transport.flush()

    def finish(self) -> None:
        self._emit(self.engine.flush())
        super().finish()

    def _emit(self, alerts: Iterable[Alert]) -> None:
        for alert in alerts:
            self.publish(Topic.ALERTS, alert.id, alert)

    @property
    def engine_counts(self) -> dict[str, int]:
        return self.engine.stats.as_dict()


# ---------------------------------------------------------------------- incidents


def hold_time(rules: Iterable[CompiledRule], gap: timedelta, lateness: timedelta) -> timedelta:
    """How far the stream must move past an alert group before the group is final.

    A later alert can join a group if it starts within ``gap`` of the group's end; a threshold or
    sequence alert starts up to its window before it is raised, and events may arrive up to
    ``lateness`` out of order.
    """
    windows = [timedelta(0)]
    for rule in rules:
        if rule.aggregate is not None:
            windows.append(rule.aggregate.window)
        if rule.sequence is not None:
            windows.append(rule.sequence.within)
    return gap + max(windows) + lateness


class IncidentStage(Stage):
    """``events`` + ``alerts`` -> ``incidents``: group alerts once their group can no longer grow.

    The stage remembers the events (as the batch command does) and holds alerts until the newest
    alert time has moved :func:`hold_time` past a group's last alert, or, with ``idle_close``
    (live logs), until that many seconds have passed without new alerts. Then it builds the
    incidents with the same :class:`IncidentBuilder` as ``prohori incidents``.
    """

    name = "incidents"
    inputs = (Topic.ALERTS, Topic.EVENTS)
    stateful = True

    def __init__(
        self,
        transport: Transport,
        rules: Sequence[CompiledRule],
        *,
        settings: IncidentSettings | None = None,
        lateness: timedelta,
        enricher: Enricher | None = None,
        enrichment: str = "none",
        clock: Callable[[], float] = time.monotonic,
        idle_close: float | None = None,
    ) -> None:
        super().__init__(transport)
        self.rules = list(rules)
        self.settings = settings or IncidentSettings()
        self.hold = hold_time(self.rules, self.settings.gap, lateness)
        self.enricher = enricher
        self.enrichment = enrichment
        self.clock = clock
        self.idle_close = idle_close
        self._reset()

    def _reset(self) -> None:
        self.context = EventContext()
        self.pending: dict[str, Alert] = {}
        self.done = _Seen(MAX_DONE_ALERTS)
        self.watermark: datetime | None = None
        self.last_alert_at = self.clock()

    def start(self) -> None:
        super().start()
        self._reset()

    def step(self, max_records: int) -> int:
        # Alerts first, then every event up to the end of the topic: the events behind an alert
        # are always published before the alert, so they are in the context when it is handled.
        alerts = self.transport.poll(Topic.ALERTS, self.group, max_records)
        count = 0
        for events in self.transport.batches_to_end(Topic.EVENTS, self.group, max_records):
            count += self._process([(Topic.EVENTS, events)])
        return count + self._process([(Topic.ALERTS, alerts)])

    def handle(self, topic: Topic, value: Mapping[str, Any]) -> None:
        if topic is Topic.EVENTS:
            self.context.add(Event.model_validate(value))
            return
        alert = Alert.model_validate(value)
        if alert.id in self.done or alert.id in self.pending:
            self.metrics.duplicates += 1
            return
        self.pending[alert.id] = alert
        self.last_alert_at = self.clock()
        if self.watermark is None or alert.last_seen > self.watermark:
            self.watermark = alert.last_seen

    def tick(self) -> None:
        if not self.pending or self.watermark is None:
            return
        quiet = self.clock() - self.last_alert_at
        if self.idle_close is not None and quiet >= self.idle_close:
            self._close(self.pending.values())
            return
        horizon = self.watermark - self.hold
        groups = group_alerts(
            self.pending.values(),
            self.context,
            gap=self.settings.gap,
            max_ip_fanout=self.settings.max_ip_fanout,
        )
        final = [
            a for g in groups if max(x.last_seen for x in g.alerts) < horizon for a in g.alerts
        ]
        if final:
            self._close(final)

    def finish(self) -> None:
        if self.pending:
            self._close(self.pending.values())
        super().finish()

    def _close(self, alerts: Iterable[Alert]) -> None:
        closing = list(alerts)
        builder = IncidentBuilder(
            self.rules, context=self.context, enricher=self.enricher, settings=self.settings
        )
        incidents = with_provenance(
            builder.build(closing), inputs=[], rules=self.rules, enrichment=self.enrichment
        )
        for alert in closing:
            self.pending.pop(alert.id, None)
            self.done.add(alert.id)
        for incident in incidents:
            self.publish(Topic.INCIDENTS, incident.id, incident)
