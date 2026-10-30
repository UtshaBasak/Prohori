"""Turn alerts into scored, ATT&CK-mapped incidents with recommended actions.

The output depends only on the input: no clock is read, everything is sorted, and the incident
id is a hash of the alert ids. (Online enrichment adds retrieval times, which naturally differ
between runs.)
"""

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import timedelta
from typing import TypeVar

from prohori.enrich import Enricher, EnrichmentReport, parse_ip
from prohori.enrich.enricher import NOT_PUBLIC_NOTE
from prohori.incidents.attack import map_attack
from prohori.incidents.events import EventContext
from prohori.incidents.grouping import (
    DEFAULT_GAP,
    DEFAULT_MAX_IP_FANOUT,
    AlertGroup,
    group_alerts,
)
from prohori.incidents.novelty import SIGNIN_SUCCESS_ACTIONS, Novelty, NoveltyStatus
from prohori.incidents.runbooks import RuleGuidance, load_guidance
from prohori.incidents.scoring import Score, score_incident
from prohori.incidents.summary import EventSummary
from prohori.rules import CompiledRule
from prohori.schema import (
    Alert,
    Confidence,
    DetectorKind,
    Incident,
    Indicator,
    IndicatorType,
    Severity,
    TimelineEntry,
    incident_id,
)

OFFLINE_PROVIDER = "offline"

T = TypeVar("T")


@dataclass(frozen=True)
class IncidentSettings:
    """Limits and windows for the incident builder."""

    gap: timedelta = DEFAULT_GAP
    max_ip_fanout: int = DEFAULT_MAX_IP_FANOUT
    max_timeline_events: int = 200  # first and last halves are kept
    max_entity_values: int = 50  # per field
    max_user_agents: int = 10
    max_lookups: int = 100  # distinct IP addresses enriched per run
    max_actions: int = 15
    max_limitations: int = 25


class IncidentBuilder:
    """Groups alerts into incidents and fills in everything a report needs.

    Args:
        rules: The rules that produced the alerts, for runbooks and false positives.
        context: Events seen in the run (see :class:`EventContext`); without it there is no
            timeline, novelty or log-source check.
        enricher: Looks up the incidents' IP addresses; each address is looked up once per run.
    """

    def __init__(
        self,
        rules: Iterable[CompiledRule] = (),
        *,
        context: EventContext | None = None,
        enricher: Enricher | None = None,
        settings: IncidentSettings | None = None,
    ) -> None:
        self.guidance = load_guidance(rules)
        self.context = context
        self.enricher = enricher
        self.settings = settings or IncidentSettings()

    def build(self, alerts: Iterable[Alert]) -> list[Incident]:
        groups = group_alerts(
            alerts,
            self.context,
            gap=self.settings.gap,
            max_ip_fanout=self.settings.max_ip_fanout,
        )
        groups.sort(key=lambda g: (g.alerts[0].first_seen, g.alerts[0].id))
        reports, not_looked_up = self._enrich(groups)
        incidents = [self._incident(g, reports, not_looked_up) for g in groups]
        return sorted(incidents, key=lambda i: (i.first_seen, i.id))

    # ------------------------------------------------------------------ enrichment

    def _enrich(self, groups: Sequence[AlertGroup]) -> tuple[dict[str, EnrichmentReport], set[str]]:
        reports: dict[str, EnrichmentReport] = {}
        skipped: set[str] = set()
        if self.enricher is None:
            return reports, skipped
        for ip in _unique(v for g in groups for f, v in g.keys if f == "source.ip"):
            if len(reports) >= self.settings.max_lookups:
                skipped.add(ip)
                continue
            try:
                parse_ip(ip)
            except ValueError:
                continue
            reports[ip] = self.enricher.enrich_ip(ip)
        return reports, skipped

    # ------------------------------------------------------------------ one incident

    def _incident(
        self, group: AlertGroup, reports: dict[str, EnrichmentReport], skipped: set[str]
    ) -> Incident:
        alerts = group.alerts
        events, missing = self._events(alerts)
        ips = [v for f, v in group.keys if f == "source.ip"]
        enrichment = {ip: reports[ip].indicator.enrichment for ip in ips if ip in reports}
        novelty = self._novelty(events)
        score = score_incident(alerts, events, group.keys, enrichment, novelty)
        mapping = map_attack(tag for a in alerts for tag in a.attack)
        limitations = [
            *self._enrichment_limitations(ips, reports, skipped),
            *self._event_limitations(events, missing),
            *_novelty_limitations(novelty),
            *(
                f"{ip} was seen with {n} accounts and is treated as shared (NAT, proxy or VPN): "
                "it does not link further alerts"
                for ip, n in group.shared_ips
            ),
            *(
                f"ATT&CK tag {tag} is not in the verified ATT&CK v{mapping.version} list"
                for tag in mapping.unverified
            ),
            *self._false_positives(alerts),
            *_model_limitations(alerts),
        ]
        return Incident(
            id=incident_id(a.id for a in alerts),
            title=_title(alerts),
            severity=score.severity,
            score=score.total,
            score_breakdown=score.components,
            first_seen=min(a.first_seen for a in alerts),
            last_seen=max(a.last_seen for a in alerts),
            entities=self._entities(group, events),
            alerts=alerts,
            timeline=self._timeline(alerts, events),
            indicators=self._indicators(ips, reports, events),
            attack=mapping.tags,
            attack_version=mapping.version if mapping.tags else None,
            recommended_actions=self._actions(alerts, events),
            confidence=_confidence(alerts, events, score),
            limitations=_unique(limitations)[: self.settings.max_limitations],
        )

    def _events(self, alerts: Sequence[Alert]) -> tuple[list[EventSummary], int]:
        if self.context is None:
            return [], 0
        found: dict[str, EventSummary] = {}
        missing = 0
        for event_id in _unique(e for a in alerts for e in a.event_ids):
            summary = self.context.get(event_id)
            if summary is None:
                missing += 1
            else:
                found[event_id] = summary
        return sorted(found.values(), key=lambda e: (e.timestamp, e.id)), missing

    def _novelty(self, events: Sequence[EventSummary]) -> list[Novelty]:
        if self.context is None:
            return []
        results: dict[tuple[str, str | None, str | None], Novelty] = {}
        for event in events:
            if event.action not in SIGNIN_SUCCESS_ACTIONS:
                continue
            result = self.context.history.check(event)
            if result is not None:
                results.setdefault((result.account, result.ip, result.client), result)
        return list(results.values())

    def _entities(
        self, group: AlertGroup, events: Sequence[EventSummary]
    ) -> dict[str, tuple[str, ...]]:
        values: dict[str, set[str]] = {}
        for alert in group.alerts:
            for field, value in alert.entities.items():
                values.setdefault(field, set()).add(value)
        for field, value in group.keys:
            values.setdefault(field, set()).add(value)
        limit = self.settings.max_entity_values
        capped = {f: set(sorted(v)[:limit]) for f, v in values.items()}
        # Accounts and addresses of successful sign-ins are named in score reasons and
        # limitations (novelty), so they are always listed: redaction collects values from here.
        for event in events:
            if event.action in SIGNIN_SUCCESS_ACTIONS:
                pairs: tuple[tuple[str, str | None], ...] = (
                    ("user.id", event.user_id),
                    ("user.name", event.user_name),
                    ("source.ip", event.source_ip),
                )
                for field, found in pairs:
                    if found is not None:
                        capped.setdefault(field, set()).add(found)
        return {f: tuple(sorted(v)) for f, v in sorted(capped.items())}

    def _timeline(
        self, alerts: Sequence[Alert], events: Sequence[EventSummary]
    ) -> tuple[TimelineEntry, ...]:
        limit = self.settings.max_timeline_events
        shown = list(events)
        if len(shown) > limit:
            shown = shown[: limit // 2] + shown[len(shown) - (limit - limit // 2) :]
        entries = [
            (
                e.timestamp,
                0,
                e.id,
                TimelineEntry(
                    timestamp=e.timestamp,
                    description=_describe(e),
                    event_id=e.id,
                    account=e.account,
                    source_ip=e.source_ip,
                ),
            )
            for e in shown
        ]
        entries.extend(
            (
                a.last_seen,
                1,
                a.id,
                TimelineEntry(
                    timestamp=a.last_seen,
                    description=f"Alert {a.detector_id} ({a.severity.value}): {a.title}",
                    alert_id=a.id,
                ),
            )
            for a in alerts
        )
        return tuple(entry for *_, entry in sorted(entries, key=lambda item: item[:3]))

    def _indicators(
        self,
        ips: Sequence[str],
        reports: dict[str, EnrichmentReport],
        events: Sequence[EventSummary],
    ) -> tuple[Indicator, ...]:
        indicators = [
            reports[ip].indicator if ip in reports else Indicator(type=IndicatorType.IP, value=ip)
            for ip in ips
        ]
        agents = sorted({e.user_agent for e in events if e.user_agent})
        indicators.extend(
            Indicator(type=IndicatorType.USER_AGENT, value=agent)
            for agent in agents[: self.settings.max_user_agents]
        )
        return tuple(indicators)

    def _actions(self, alerts: Sequence[Alert], events: Sequence[EventSummary]) -> tuple[str, ...]:
        ordered = sorted(alerts, key=lambda a: (-a.severity.rank, a.first_seen, a.id))
        actions = [
            action
            for rule_id in _unique(a.detector_id for a in ordered)
            for action in self.guidance.get(rule_id, RuleGuidance(rule_id)).actions
            if _applies(action, events)
        ]
        if any(a.detector_kind is DetectorKind.MODEL for a in alerts):
            actions.append(MODEL_ACTION)
        return tuple(_unique(actions)[: self.settings.max_actions])

    def _false_positives(self, alerts: Sequence[Alert]) -> list[str]:
        return [
            f"Possible benign cause for {rule_id}: {cause}"
            for rule_id in sorted({a.detector_id for a in alerts})
            for cause in self.guidance.get(rule_id, RuleGuidance(rule_id)).false_positives
        ]

    def _enrichment_limitations(
        self, ips: Sequence[str], reports: dict[str, EnrichmentReport], skipped: set[str]
    ) -> list[str]:
        if not ips:
            return []
        if self.enricher is None:
            return ["Enrichment not run: IP reputation and location were not considered"]
        notes = [f"Enrichment: {note}" for note in self.enricher.setup_notes]
        if self.enricher.offline:
            notes.append(
                "Enrichment offline: only bundled demo data, local GeoLite2 data and cached "
                "answers were used"
            )
        demo = [ip for ip in ips if ip in reports and _has_provider(reports[ip], OFFLINE_PROVIDER)]
        if demo:
            notes.append(
                f"Enrichment of {', '.join(demo)} is bundled demo data, not real reputation"
            )
        for ip in ips:
            if ip in reports:
                notes.extend(
                    f"Enrichment of {ip}: {note}"
                    for note in reports[ip].notes
                    if note != NOT_PUBLIC_NOTE and not note.endswith("(offline)")
                )
        late = [ip for ip in ips if ip in skipped]
        if late:
            notes.append(
                f"Not enriched (limit of {self.settings.max_lookups} addresses per run): "
                + ", ".join(late)
            )
        return notes

    def _event_limitations(self, events: Sequence[EventSummary], missing: int) -> list[str]:
        if self.context is None:
            return ["Matched events were not available: no timeline, novelty or log-source checks"]
        notes: list[str] = []
        if missing:
            notes.append(
                f"{missing} matched event(s) were no longer in memory; the timeline is incomplete"
            )
        sources = sorted({e.log_source for e in events})
        if len(sources) == 1:
            notes.append(f"Single log source ({sources[0]}): no other log corroborates it")
        if len(events) > self.settings.max_timeline_events:
            notes.append(
                f"The timeline shows {self.settings.max_timeline_events} of {len(events)} "
                "matched events (the earliest and the latest)"
            )
        return notes


def build_incidents(
    alerts: Iterable[Alert],
    rules: Iterable[CompiledRule] = (),
    *,
    context: EventContext | None = None,
    enricher: Enricher | None = None,
    settings: IncidentSettings | None = None,
) -> list[Incident]:
    """Group ``alerts`` into incidents (see :class:`IncidentBuilder`)."""
    return IncidentBuilder(rules, context=context, enricher=enricher, settings=settings).build(
        alerts
    )


def _unique(items: Iterable[T]) -> list[T]:
    return list(dict.fromkeys(items))


#: Runbook bullets that start with these prefixes apply only to SSH or only to the web app.
SSH_ONLY_PREFIX = "For SSH,"
APP_ONLY_PREFIX = "For the web app,"


def _is_ssh(event: EventSummary) -> bool:
    return event.action.startswith("ssh.") or event.log_source == "sshd"


def _applies(action: str, events: Sequence[EventSummary]) -> bool:
    """Drop SSH-only actions from web incidents and web-only ones from SSH incidents."""
    if not events:  # without the events, keep everything
        return True
    if action.startswith(SSH_ONLY_PREFIX):
        return any(_is_ssh(e) for e in events)
    if action.startswith(APP_ONLY_PREFIX):
        return any(not _is_ssh(e) for e in events)
    return True


def _has_provider(report: EnrichmentReport, provider: str) -> bool:
    return any(result.provider == provider for result in report.indicator.enrichment)


def _title(alerts: Sequence[Alert]) -> str:
    primary = min(alerts, key=lambda a: (-a.severity.rank, a.first_seen, a.id))
    others = len(alerts) - 1
    if not others:
        return primary.title
    return f"{primary.title} and {others} related alert{'s' if others > 1 else ''}"


def _describe(event: EventSummary) -> str:
    action = event.action if event.outcome == "unknown" else f"{event.action} ({event.outcome})"
    parts = [f"[{event.log_source}] {action}"]
    if event.account:
        parts.append(f"account {event.account}")
    if event.source_ip:
        parts.append(f"from {event.source_ip}")
    if event.http_path:
        request = " ".join(p for p in (event.http_method, event.http_path) if p)
        if event.http_status is not None:
            request += f" -> {event.http_status}"
        parts.append(request)
    if event.client:
        parts.append(f"client {event.client}")
    return ", ".join(parts)


def _confidence(
    alerts: Sequence[Alert], events: Sequence[EventSummary], score: Score
) -> Confidence:
    rules = {a.detector_id for a in alerts}
    sources = {e.log_source for e in events}
    corroborated = len(sources) > 1 or score.reputation_points > 0 or score.success_after_failure
    if len(rules) > 1 and corroborated:
        return Confidence.HIGH
    top = max(a.severity.rank for a in alerts)
    if len(alerts) == 1 and top <= Severity.MEDIUM.rank and not score.reputation_points:
        return Confidence.LOW
    return Confidence.MEDIUM


#: Anomaly detectors have no runbook; this is their guidance.
MODEL_ACTION = (
    "Review the events in the window an anomaly detector flagged and decide whether the activity "
    "is expected (a shared NAT or proxy address, a crawler, a batch job) before acting on it."
)


def _model_limitations(alerts: Sequence[Alert]) -> list[str]:
    detectors = sorted({a.detector_id for a in alerts if a.detector_kind is DetectorKind.MODEL})
    if not detectors:
        return []
    return [
        f"Raised by an anomaly detector ({', '.join(detectors)}): the activity is unusual "
        "compared with the rest of this log, which is not proof of an attack"
    ]


def _novelty_limitations(novelty: Sequence[Novelty]) -> list[str]:
    notes: list[str] = []
    for item in novelty:
        if item.ip_status is NoveltyStatus.NO_HISTORY:
            notes.append(
                f"No earlier sign-in to {item.account} in the input: could not tell whether "
                f"{item.ip or 'the address'} is new for it"
            )
        elif item.ip_status is NoveltyStatus.UNKNOWN:
            notes.append(f"Sign-in history limits reached for {item.account}: novelty not checked")
    return notes
