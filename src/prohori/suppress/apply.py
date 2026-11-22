# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Apply suppression entries to alerts, after detection, the same way in batch and stream.

An alert is suppressed by the first entry (in file order) that

* covers the alert's detector (its rule id is listed, or the entry says ``*``),
* is in force on the day of the alert's last event (UTC), and
* matches **every** event the alert lists, or matches the alert's entities. Entities are the
  values every event of the alert shares (the group of a threshold or sequence rule, the fields
  of a single-event rule, the address of a model window), so they decide when the event list is
  incomplete (an alert lists at most 100 events) or its events were not seen.

A suppressed alert is never dropped: it is returned marked (``alert.suppression``), counted per
entry and rule, and the first :data:`MAX_LISTED` are kept for listing. Callers keep suppressed
alerts out of incidents. Other alerts about the same entities are untouched, so a suppression
cannot hide an incident's other alerts.

The suppressor remembers which entries each event matched, for at most
:data:`MAX_TRACKED_EVENTS` matching events (the oldest are forgotten first). An alert whose events
were forgotten falls back to its entities, and is not suppressed when they do not decide.
"""

from collections import Counter, OrderedDict
from collections.abc import Iterable, Iterator
from typing import Any

from prohori.ml.features import MAX_WINDOW_EVENT_IDS
from prohori.rules.engine import MAX_ALERT_EVENT_IDS
from prohori.schema import Alert, Event, SuppressionMark
from prohori.suppress.entries import Entry
from prohori.suppress.loader import NO_SUPPRESSIONS, Suppressions

#: Events (that matched at least one entry) whose matches are remembered.
MAX_TRACKED_EVENTS = 200_000
#: Suppressed alerts kept for listing; the rest are only counted.
MAX_LISTED = 1_000
#: Rules and models list at most this many events per alert; a shorter list is complete.
COMPLETE_BELOW = min(MAX_ALERT_EVENT_IDS, MAX_WINDOW_EVENT_IDS)


class Suppressor:
    """Watches the events going to the detectors and marks the alerts that come out."""

    def __init__(
        self,
        suppressions: Suppressions = NO_SUPPRESSIONS,
        *,
        max_tracked: int = MAX_TRACKED_EVENTS,
        max_listed: int = MAX_LISTED,
    ) -> None:
        self.entries: tuple[Entry, ...] = suppressions.entries
        self.max_tracked = max_tracked
        self.max_listed = max_listed
        self._matched: OrderedDict[str, frozenset[int]] = OrderedDict()
        #: Suppressed alerts per entry id, and per (entry id, detector id).
        self.counts: Counter[str] = Counter()
        self.by_rule: Counter[tuple[str, str]] = Counter()
        #: The first ``max_listed`` suppressed alerts.
        self.listed: list[Alert] = []
        #: Matching events forgotten to keep memory bounded.
        self.forgotten = 0

    def __bool__(self) -> bool:
        return bool(self.entries)

    @property
    def total(self) -> int:
        return self.counts.total()

    # ------------------------------------------------------------------ events

    def observe(self, events: Iterable[Event]) -> Iterator[Event]:
        """Pass ``events`` through, remembering which entries each one matches."""
        for event in events:
            self.observe_one(event)
            yield event

    def observe_one(self, event: Event) -> None:
        if not self.entries:
            return
        hits = frozenset(i for i, entry in enumerate(self.entries) if entry.matches(event))
        if not hits:
            return
        self._matched[event.id] = hits
        self._matched.move_to_end(event.id)
        if len(self._matched) > self.max_tracked:
            self._matched.popitem(last=False)
            self.forgotten += 1

    # ------------------------------------------------------------------ alerts

    def entry_for(self, alert: Alert) -> Entry | None:
        """The entry that suppresses ``alert``, or None."""
        for index, entry in enumerate(self.entries):
            if not entry.covers(alert.detector_id) or not entry.in_force(alert.last_seen):
                continue
            complete = len(alert.event_ids) < COMPLETE_BELOW
            if complete and all(index in self._matched.get(e, ()) for e in alert.event_ids):
                return entry
            if entry.matches_values(alert.entities):
                return entry
        return None

    def apply(self, alert: Alert) -> Alert:
        """``alert``, marked if an entry suppresses it (and counted)."""
        if not self.entries or alert.suppression is not None:
            return alert
        entry = self.entry_for(alert)
        if entry is None:
            return alert
        mark = SuppressionMark(
            id=entry.id, reason=entry.reason, owner=entry.owner, expires=entry.expires
        )
        marked = alert.model_copy(update={"suppression": mark})
        self.counts[entry.id] += 1
        self.by_rule[(entry.id, alert.detector_id)] += 1
        if len(self.listed) < self.max_listed:
            self.listed.append(marked)
        return marked

    def apply_all(self, alerts: Iterable[Alert]) -> Iterator[Alert]:
        for alert in alerts:
            yield self.apply(alert)

    def summary(self) -> dict[str, Any]:
        """Counters for a run's JSON summary: the total, and per entry the count per rule."""
        by_entry: dict[str, dict[str, int]] = {}
        for (entry, rule), count in sorted(self.by_rule.items()):
            by_entry.setdefault(entry, {})[rule] = count
        return {"suppressed": self.total, "suppressed_by_entry": by_entry}

    def rows(self) -> list[tuple[Entry, str, int]]:
        """(entry, rule, count) for every entry and rule that suppressed something."""
        by_id = {e.id: e for e in self.entries}
        return [(by_id[e], r, n) for (e, r), n in sorted(self.by_rule.items())]
