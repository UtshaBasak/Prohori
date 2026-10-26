"""Single-pass, bounded-state evaluation of compiled rules over a stream of events.

Evaluation semantics (see ``docs/RULES.md``, "Evaluation semantics"):

* **Order.** Events reach rules in one total order: by timestamp, ties broken by event id. A
  reorder buffer holds events until the *watermark* (the newest timestamp seen) has moved
  ``lateness`` past them, so any arrival order within that bound gives identical alerts.
* **Late events.** An event that arrives with a timestamp at least ``watermark - lateness`` is
  never late. One that sorts before an event already released is dropped and counted in
  :attr:`EngineStats.late_events`.
* **Future events.** With a ``reference_time``, events more than ``max_future`` after it are
  dropped and counted in :attr:`EngineStats.future_events`, so one bogus timestamp cannot push the
  watermark ahead and make every later event "late". The engine never reads the clock itself.
* **Windows.** An event is inside a sliding window at time ``t`` when ``t - event.timestamp <
  window``. Tumbling windows are aligned to the Unix epoch in UTC.
* **Re-alerting.** When a threshold or sequence fires, that group's state is cleared; the next
  alert needs the threshold to be reached again by later events. Stateless rules alert once per
  matching event.
* **Missing group fields.** An event without a value for every ``group_by`` / ``by`` field is
  skipped for that rule and counted in :attr:`EngineStats.ungrouped_events`.
"""

import heapq
from collections import OrderedDict, deque
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from prohori.rules.compiler import CompiledRule
from prohori.rules.model import AggregateSpec, SequenceSpec, WindowMode
from prohori.schema import Alert, DetectorKind, Event, Severity, get_field

#: Event ids kept in one alert (the most recent ones); the explanation gives the full count.
MAX_ALERT_EVENT_IDS = 100
#: Events kept per group for ratio thresholds (older ones are dropped and counted).
MAX_GROUP_EVENTS = 10_000
#: Fields copied into the entities of alerts from stateless rules, when present.
ENTITY_FIELDS = ("source.ip", "user.name", "user.id", "host", "request_id")

_SCORES = {Severity.LOW: 25.0, Severity.MEDIUM: 50.0, Severity.HIGH: 75.0, Severity.CRITICAL: 100.0}
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)


@dataclass
class EngineStats:
    """Counters for one engine run."""

    events_in: int = 0
    events_evaluated: int = 0
    late_events: int = 0
    future_events: int = 0
    ungrouped_events: int = 0
    groups_expired: int = 0
    groups_evicted: int = 0
    group_events_dropped: int = 0
    buffer_overflows: int = 0
    alerts: int = 0

    def as_dict(self) -> dict[str, int]:
        return dict(self.__dict__)


@dataclass(frozen=True, slots=True)
class _Seen:
    timestamp: datetime
    event_id: str


def _group_key(event: Event, fields: Sequence[str]) -> tuple[str, ...] | None:
    values: list[str] = []
    for path in fields:
        value = get_field(event, path)
        if value is None:
            return None
        values.append(str(value))
    return tuple(values)


def _build_alert(
    rule: CompiledRule,
    seen: Sequence[_Seen],
    total: int,
    entities: dict[str, str],
    explanation: str,
    first_seen: datetime | None = None,
) -> Alert:
    kept = list(seen)[-MAX_ALERT_EVENT_IDS:]
    meta = rule.meta
    return Alert(
        detector_id=meta.id,
        detector_kind=DetectorKind.RULE,
        title=meta.title,
        severity=meta.severity,
        score=_SCORES[meta.severity],
        event_ids=tuple(s.event_id for s in kept),
        entities=entities,
        first_seen=first_seen or seen[0].timestamp,
        last_seen=seen[-1].timestamp,
        attack=meta.attack_tags,
        explanation=explanation
        if total <= len(kept)
        else f"{explanation} (showing the last {len(kept)} event ids)",
    )


def _describe(fields: Sequence[str], key: tuple[str, ...]) -> str:
    return ", ".join(f"{f}={v}" for f, v in zip(fields, key, strict=True))


# ---------------------------------------------------------------- per-rule evaluators


class _Evaluator:
    def __init__(self, rule: CompiledRule, stats: EngineStats, max_groups: int) -> None:
        self.rule = rule
        self.stats = stats
        self.max_groups = max_groups

    def process(self, event: Event) -> list[Alert]:  # pragma: no cover - overridden
        raise NotImplementedError

    def state_size(self) -> int:
        return 0


class _StatelessEvaluator(_Evaluator):
    def process(self, event: Event) -> list[Alert]:
        if not self.rule.matches_filter(event):
            return []
        entities = {}
        for path in ENTITY_FIELDS:
            value = get_field(event, path)
            if value is not None:
                entities[path] = str(value)
        seen = [_Seen(event.timestamp, event.id)]
        return [
            _build_alert(self.rule, seen, 1, entities, f"{event.event.action} matched the rule")
        ]


class _AggregateGroup:
    __slots__ = ("bucket", "distinct", "first_ts", "last_seen", "ratio_hits", "seen")

    def __init__(self) -> None:
        self.seen: deque[_Seen] = deque()
        self.distinct: OrderedDict[str, datetime] = OrderedDict()
        self.ratio_hits: deque[bool] = deque()
        self.bucket: int | None = None
        self.last_seen: datetime = _EPOCH
        # Earliest counted event, kept separately because evidence ids may be trimmed.
        self.first_ts: datetime | None = None

    def size(self) -> int:
        return len(self.seen) + len(self.distinct)


class _AggregateEvaluator(_Evaluator):
    def __init__(self, rule: CompiledRule, stats: EngineStats, max_groups: int) -> None:
        super().__init__(rule, stats, max_groups)
        if rule.aggregate is None:
            msg = f"rule {rule.id} has no aggregate block"
            raise ValueError(msg)
        self.spec: AggregateSpec = rule.aggregate
        self.groups: OrderedDict[tuple[str, ...], _AggregateGroup] = OrderedDict()

    def state_size(self) -> int:
        return sum(g.size() for g in self.groups.values()) + len(self.groups)

    def _expire_groups(self, now: datetime) -> None:
        window = self.spec.window
        while self.groups:
            key, group = next(iter(self.groups.items()))
            if now - group.last_seen < window:
                break
            del self.groups[key]
            self.stats.groups_expired += 1

    def _group(self, key: tuple[str, ...], now: datetime) -> _AggregateGroup:
        group = self.groups.pop(key, None)
        if group is None:
            group = _AggregateGroup()
            if len(self.groups) >= self.max_groups:
                self.groups.popitem(last=False)
                self.stats.groups_evicted += 1
        group.last_seen = now
        self.groups[key] = group  # most recently used at the end
        return group

    def _slide(self, group: _AggregateGroup, now: datetime) -> None:
        window = self.spec.window
        if self.spec.mode is WindowMode.TUMBLING:
            bucket = (now - _EPOCH) // window
            if group.bucket != bucket:
                group.bucket = bucket
                group.first_ts = None
                group.seen.clear()
                group.distinct.clear()
                group.ratio_hits.clear()
            return
        while group.seen and now - group.seen[0].timestamp >= window:
            group.seen.popleft()
            if group.ratio_hits:
                group.ratio_hits.popleft()
        while group.distinct:
            value, last = next(iter(group.distinct.items()))
            if now - last < window:
                break
            del group.distinct[value]
        if group.first_ts is not None and now - group.first_ts >= window:
            group.first_ts = None  # left the window; fall back to the oldest evidence kept

    def process(self, event: Event) -> list[Alert]:
        now = event.timestamp
        self._expire_groups(now)
        if not self.rule.matches_filter(event):
            return []
        key = _group_key(event, self.spec.group_by)
        if key is None:
            self.stats.ungrouped_events += 1
            return []
        group = self._group(key, now)
        self._slide(group, now)
        group.seen.append(_Seen(now, event.id))
        if group.first_ts is None:
            group.first_ts = group.seen[0].timestamp
        spec = self.spec
        fired = False
        detail = ""
        if spec.count_gte is not None:
            fired = len(group.seen) >= spec.count_gte
            detail = f"{len(group.seen)} matching events (threshold {spec.count_gte})"
        elif spec.distinct is not None:
            value = get_field(event, spec.distinct.field)
            if value is not None:
                group.distinct.pop(str(value), None)
                group.distinct[str(value)] = now
            fired = len(group.distinct) >= spec.distinct.gte
            detail = (
                f"{len(group.distinct)} distinct {spec.distinct.field} values "
                f"(threshold {spec.distinct.gte})"
            )
        elif spec.ratio is not None:
            group.ratio_hits.append(self.rule.selection_matches(spec.ratio.selection, event))
            if len(group.seen) > MAX_GROUP_EVENTS:
                group.seen.popleft()
                group.ratio_hits.popleft()
                self.stats.group_events_dropped += 1
            total = len(group.ratio_hits)
            hits = sum(group.ratio_hits)
            fired = total >= spec.ratio.min_count and hits / total >= spec.ratio.gte
            detail = (
                f"{hits} of {total} events matched {spec.ratio.selection} "
                f"(threshold {spec.ratio.gte:.0%}, minimum {spec.ratio.min_count})"
            )
        if not fired:
            if spec.distinct is not None and len(group.seen) > MAX_ALERT_EVENT_IDS:
                group.seen.popleft()  # distinct thresholds only need recent ids as evidence
            return []
        mode = "window" if spec.mode is WindowMode.SLIDING else "tumbling window"
        explanation = (
            f"{detail} for {_describe(spec.group_by, key)} within a "
            f"{_format_duration(spec.window)} {mode}"
        )
        alert = _build_alert(
            self.rule,
            list(group.seen),
            len(group.seen),
            dict(zip(spec.group_by, key, strict=True)),
            explanation,
            first_seen=group.first_ts,
        )
        del self.groups[key]  # re-alert only after the threshold is reached again
        return [alert]


class _SequenceGroup:
    __slots__ = ("count", "extra", "first", "last_seen", "matched", "prefix", "start", "step")

    def __init__(self) -> None:
        self.step = 0
        self.count = 0
        self.first: deque[_Seen] = deque()
        self.matched: list[_Seen] = []
        self.start: datetime | None = None
        self.last_seen: datetime = _EPOCH
        self.prefix: list[_Seen] = []  # after completion: the events of every step but the last
        self.extra: list[_Seen] = []  # after completion: further final-step events

    def size(self) -> int:
        return len(self.first) + len(self.matched) + len(self.extra)


class _SequenceEvaluator(_Evaluator):
    """Ordered steps per entity.

    * Step 1 keeps a sliding list of its matches within ``within``; when it reaches its count,
      the sequence starts at the oldest of those matches.
    * Later steps must complete before ``start + within``; an event at or after that moment
      expires the sequence, which restarts with that event as a possible first step.
    * After step 1 has completed, further step-1 events are ignored.
    * An event matching several steps counts for the current step.
    * After the sequence completes, until ``start + within``, every further ``count_gte`` events
      matching the last step raise another alert with the earlier steps' events: a second
      account change after one sign-in is reported too, not swallowed.
    """

    def __init__(self, rule: CompiledRule, stats: EngineStats, max_groups: int) -> None:
        super().__init__(rule, stats, max_groups)
        if rule.sequence is None:
            msg = f"rule {rule.id} has no sequence block"
            raise ValueError(msg)
        self.spec: SequenceSpec = rule.sequence
        self.groups: OrderedDict[tuple[str, ...], _SequenceGroup] = OrderedDict()

    def state_size(self) -> int:
        return sum(g.size() for g in self.groups.values()) + len(self.groups)

    def _expire_groups(self, now: datetime) -> None:
        within = self.spec.within
        while self.groups:
            key, group = next(iter(self.groups.items()))
            if now - group.last_seen < within:
                break
            del self.groups[key]
            self.stats.groups_expired += 1

    def process(self, event: Event) -> list[Alert]:
        now = event.timestamp
        self._expire_groups(now)
        if not self.rule.matches_filter(event):
            return []
        key = _group_key(event, self.spec.by)
        if key is None:
            self.stats.ungrouped_events += 1
            return []
        group = self.groups.pop(key, None)
        if group is None:
            group = _SequenceGroup()
            if len(self.groups) >= self.max_groups:
                self.groups.popitem(last=False)
                self.stats.groups_evicted += 1
        group.last_seen = now
        self.groups[key] = group
        steps = self.spec.steps
        within = self.spec.within

        if group.step > 0 and group.start is not None and now - group.start >= within:
            group = _SequenceGroup()  # expired: start over with this event
            group.last_seen = now
            self.groups[key] = group

        if group.step == 0:
            first = steps[0]
            if not self.rule.selection_matches(first.selection, event):
                return []
            group.first.append(_Seen(now, event.id))
            while group.first and now - group.first[0].timestamp >= within:
                group.first.popleft()
            if len(group.first) < first.count_gte:
                return []
            group.start = group.first[0].timestamp
            group.matched = list(group.first)
            group.first.clear()
            group.step, group.count = 1, 0
            return []

        if group.step == len(steps):  # completed; later final-step events raise further alerts
            last = steps[-1]
            if not self.rule.selection_matches(last.selection, event):
                return []
            group.extra.append(_Seen(now, event.id))
            if len(group.extra) < last.count_gte:
                return []
            seen, group.extra = group.prefix + group.extra, []
            return [self._alert(seen, key)]

        step = steps[group.step]
        if not self.rule.selection_matches(step.selection, event):
            return []
        group.matched.append(_Seen(now, event.id))
        group.count += 1
        if group.count < step.count_gte:
            return []
        group.step, group.count = group.step + 1, 0
        if group.step < len(steps):
            return []
        group.prefix = group.matched[: len(group.matched) - steps[-1].count_gte]
        return [self._alert(group.matched, key)]

    def _alert(self, seen: Sequence[_Seen], key: tuple[str, ...]) -> Alert:
        steps = self.spec.steps
        names = " then ".join(f"{s.count_gte} x {s.selection}" for s in steps)
        explanation = (
            f"{names} for {_describe(self.spec.by, key)} within "
            f"{_format_duration(self.spec.within)}"
        )
        return _build_alert(
            self.rule, seen, len(seen), dict(zip(self.spec.by, key, strict=True)), explanation
        )


def _format_duration(value: timedelta) -> str:
    seconds = int(value.total_seconds())
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


# ---------------------------------------------------------------- engine


@dataclass(order=True)
class _Pending:
    timestamp: datetime
    event_id: str
    event: Event = field(compare=False)


class RuleEngine:
    """Evaluate compiled rules over events, one event at a time.

    Args:
        rules: Compiled rules to evaluate.
        lateness: How far behind the newest timestamp an event may arrive and still be processed
            in order.
        reference_time: Optional "now" for rejecting future timestamps (pass the current time for
            live data; omit for archived logs). The engine never reads the clock itself.
        max_future: How far after ``reference_time`` a timestamp may be.
        max_buffered: Upper bound on events held in the reorder buffer.
        max_groups: Upper bound on groups (entities) tracked per stateful rule.
    """

    def __init__(
        self,
        rules: Iterable[CompiledRule],
        *,
        lateness: timedelta = timedelta(0),
        reference_time: datetime | None = None,
        max_future: timedelta = timedelta(days=1),
        max_buffered: int = 100_000,
        max_groups: int = 50_000,
    ) -> None:
        if lateness < timedelta(0):
            msg = "lateness must not be negative"
            raise ValueError(msg)
        self.lateness = lateness
        self.limit = reference_time + max_future if reference_time is not None else None
        self.max_buffered = max_buffered
        self.stats = EngineStats()
        self._buffer: list[_Pending] = []
        self._watermark: datetime | None = None
        self._released: tuple[datetime, str] | None = None
        self._evaluators: list[_Evaluator] = []
        for rule in rules:
            if rule.aggregate is not None:
                self._evaluators.append(_AggregateEvaluator(rule, self.stats, max_groups))
            elif rule.sequence is not None:
                self._evaluators.append(_SequenceEvaluator(rule, self.stats, max_groups))
            else:
                self._evaluators.append(_StatelessEvaluator(rule, self.stats, max_groups))

    def process(self, event: Event) -> list[Alert]:
        """Accept one event; return the alerts raised by events released from the buffer."""
        self.stats.events_in += 1
        if self.limit is not None and event.timestamp > self.limit:
            self.stats.future_events += 1
            return []
        if self._released is not None and (event.timestamp, event.id) < self._released:
            self.stats.late_events += 1
            return []
        heapq.heappush(self._buffer, _Pending(event.timestamp, event.id, event))
        if self._watermark is None or event.timestamp > self._watermark:
            self._watermark = event.timestamp
        alerts: list[Alert] = []
        horizon = self._watermark - self.lateness
        # Strictly older than the horizon: events at the horizon may still have ties to come.
        while self._buffer and (
            self._buffer[0].timestamp < horizon or len(self._buffer) > self.max_buffered
        ):
            if len(self._buffer) > self.max_buffered and self._buffer[0].timestamp >= horizon:
                self.stats.buffer_overflows += 1
            alerts.extend(self._release(heapq.heappop(self._buffer).event))
        return alerts

    def flush(self) -> list[Alert]:
        """Release every buffered event (end of input). Safe to call more than once."""
        alerts: list[Alert] = []
        while self._buffer:
            alerts.extend(self._release(heapq.heappop(self._buffer).event))
        return alerts

    def run(self, events: Iterable[Event]) -> Iterator[Alert]:
        """Process an entire input and flush at the end."""
        for event in events:
            yield from self.process(event)
        yield from self.flush()

    def state_size(self) -> dict[str, int]:
        """Current amount of held state, for monitoring and tests."""
        return {
            "buffered_events": len(self._buffer),
            "rule_state": sum(e.state_size() for e in self._evaluators),
        }

    def _release(self, event: Event) -> list[Alert]:
        self._released = (event.timestamp, event.id)
        self.stats.events_evaluated += 1
        alerts: list[Alert] = []
        for evaluator in self._evaluators:
            alerts.extend(evaluator.process(event))
        self.stats.alerts += len(alerts)
        return alerts
