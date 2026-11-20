# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""A bound on the alerts the batch commands hold before building incidents.

``prohori incidents`` and ``triage`` collect every alert of a run before grouping them, so a log
that raises millions of alerts (a scanner hitting a stateless rule on every request) would hold
them all in memory. :class:`AlertCap` keeps at most :data:`MAX_ALERTS_PER_KEY` alerts per rule
and entities (the first ones, in the order they are raised) and at most :data:`MAX_ALERTS_HELD`
in all, and counts the rest. An incident whose rule and entities lost alerts says so in its
limitations; alerts dropped by the overall bound are reported in the run's summary.

The limits are far above anything the simulator or the samples produce (at most 14 alerts per
rule and entities), so ordinary runs are unchanged.
"""

from collections import Counter
from collections.abc import Iterable, Sequence

from prohori.schema import Alert, Incident

#: Alerts kept per rule and set of entities.
MAX_ALERTS_PER_KEY = 1_000
#: Alerts kept in all.
MAX_ALERTS_HELD = 20_000
#: Rule-and-entities keys whose dropped alerts are counted one by one; beyond it they are only
#: counted in total, so the counters stay bounded too.
MAX_COUNTED_KEYS = 10_000

AlertKey = tuple[str, tuple[tuple[str, str], ...]]


def alert_key(alert: Alert) -> AlertKey:
    """The rule and entities an alert is about."""
    return alert.detector_id, tuple(sorted(alert.entities.items()))


class AlertCap:
    """Collects alerts up to the limits and counts what it drops."""

    def __init__(self, *, per_key: int | None = None, total: int | None = None) -> None:
        # Defaults read when called, so a test can lower the module's limits.
        self.per_key = MAX_ALERTS_PER_KEY if per_key is None else per_key
        self.total = MAX_ALERTS_HELD if total is None else total
        if self.per_key < 1 or self.total < 1:
            msg = "alert limits must be at least 1"
            raise ValueError(msg)
        self.alerts: list[Alert] = []
        self._held: Counter[AlertKey] = Counter()
        self.dropped: Counter[AlertKey] = Counter()
        #: Every alert seen, kept or not.
        self.seen = 0
        #: Alerts dropped, in total (including keys not counted one by one).
        self.dropped_total = 0

    def add(self, alert: Alert) -> bool:
        """Keep ``alert`` if the limits allow it; return whether it was kept."""
        self.seen += 1
        key = alert_key(alert)
        if self._held[key] < self.per_key and len(self.alerts) < self.total:
            self._held[key] += 1
            self.alerts.append(alert)
            return True
        self.dropped_total += 1
        if key in self.dropped or len(self.dropped) < MAX_COUNTED_KEYS:
            self.dropped[key] += 1
        return False

    def extend(self, alerts: Iterable[Alert]) -> None:
        for alert in alerts:
            self.add(alert)

    def limitations(self, incident: Incident) -> list[str]:
        """What ``incident`` is missing because of the limits: one note per rule and entities."""
        notes: list[str] = []
        for key in sorted({alert_key(a) for a in incident.alerts}):
            missing = self.dropped.get(key, 0)
            if not missing:
                continue
            rule, entities = key
            about = ", ".join(f"{f}={v}" for f, v in entities) or "no entities"
            notes.append(
                f"{missing:,} more {rule} alert(s) for {about} were raised but not kept: a run "
                f"keeps at most {self.per_key:,} alerts per rule and entities and "
                f"{self.total:,} in all, so memory stays bounded"
            )
        return notes

    def apply(self, incidents: Sequence[Incident]) -> list[Incident]:
        """``incidents`` with the limits' notes added to their limitations."""
        result: list[Incident] = []
        for incident in incidents:
            notes = self.limitations(incident)
            if notes:  # validated again, so the notes are bounded like every other text
                data = incident.model_dump()
                data["limitations"] = (*incident.limitations, *notes)
                incident = Incident.model_validate(data)
            result.append(incident)
        return result
