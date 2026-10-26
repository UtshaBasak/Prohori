"""The incident builder end to end: parse -> detect -> group -> score -> map -> recommend."""

from datetime import UTC, datetime
from pathlib import Path

import pytest
from tests.unit.incidents.factories import alert, at, event

from prohori.enrich import Enricher, EnrichSettings, build_enricher
from prohori.incidents import EventContext, IncidentBuilder, IncidentSettings, build_incidents
from prohori.parsers import AppJsonParser, iter_text_lines
from prohori.rules import CompiledRule, RuleEngine, builtin_rules_dir, load_rules
from prohori.rules.attack import ATTACK_VERSION
from prohori.schema import Alert, Confidence, Incident, IndicatorType, Severity, incident_id

ROOT = Path(__file__).resolve().parents[3]
TAKEOVER = ROOT / "samples" / "logs" / "account-takeover.jsonl"


@pytest.fixture(scope="module")
def rules() -> list[CompiledRule]:
    return [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]


def _offline() -> Enricher:
    return build_enricher(EnrichSettings.load(env_file=None), offline=True)


def _detect(path: Path, rules: list[CompiledRule]) -> tuple[list[Alert], EventContext]:
    context = EventContext()
    lines = path.read_text(encoding="utf-8").splitlines()
    events = AppJsonParser().parse(iter_text_lines(lines), source=path.name)
    engine = RuleEngine(rules, reference_time=datetime(2026, 10, 27, tzinfo=UTC))
    return list(engine.run(context.observe(events))), context


def _takeover(rules: list[CompiledRule]) -> Incident:
    alerts, context = _detect(TAKEOVER, rules)
    with _offline() as enricher:
        incidents = build_incidents(alerts, rules, context=context, enricher=enricher)
    assert len(incidents) == 1
    return incidents[0]


def test_account_takeover_becomes_one_critical_incident(rules: list[CompiledRule]) -> None:
    incident = _takeover(rules)
    assert {a.detector_id for a in incident.alerts} == {
        "PRH-AUTH-001",
        "PRH-AUTH-003",
        "PRH-ACCT-001",
    }
    assert incident.severity is Severity.CRITICAL
    assert incident.score == 100
    assert sum(c.points for c in incident.score_breakdown) == incident.score
    reasons = [c.reason for c in incident.score_breakdown]
    assert "A sign-in succeeded after failed attempts" in reasons
    assert any(r.startswith("Sign-in to u-2001 from 203.0.113.7, an IP not seen") for r in reasons)
    assert any(r.startswith("Reputation of 203.0.113.7") for r in reasons)
    assert incident.confidence is Confidence.HIGH
    assert incident.entities["user.id"] == ("u-2001",)
    assert incident.entities["source.ip"] == ("203.0.113.7",)
    assert incident.attack_version == ATTACK_VERSION
    assert "attack.t1110" in incident.attack
    assert incident.recommended_actions[0] == (
        "End all sessions of the account and force a password reset."
    )  # from the most severe rule (PRH-AUTH-003) first
    assert len(set(incident.recommended_actions)) == len(incident.recommended_actions)
    assert incident.id == incident_id(a.id for a in incident.alerts)
    assert incident.title.endswith("and 2 related alerts")


def test_takeover_timeline_and_indicators(rules: list[CompiledRule]) -> None:
    incident = _takeover(rules)
    times = [e.timestamp for e in incident.timeline]
    assert times == sorted(times)
    alert_entries = [e for e in incident.timeline if e.alert_id]
    assert len(alert_entries) == 3
    assert any("account.2fa.disabled (success)" in e.description for e in incident.timeline)
    ip = incident.indicators[0]
    assert (ip.type, ip.value) == (IndicatorType.IP, "203.0.113.7")
    assert ip.enrichment[0].provider == "offline"
    agents = [i.value for i in incident.indicators if i.type is IndicatorType.USER_AGENT]
    assert agents == ["python-requests/2.32.3"]


def test_takeover_limitations(rules: list[CompiledRule]) -> None:
    limitations = _takeover(rules).limitations
    assert limitations[0].startswith("Enrichment offline")
    assert "Enrichment of 203.0.113.7 is bundled demo data, not real reputation" in limitations
    assert "Single log source (app-security): no other log corroborates it" in limitations
    assert any(x.startswith("Possible benign cause for PRH-AUTH-003") for x in limitations)


def test_same_input_gives_identical_incidents(rules: list[CompiledRule]) -> None:
    first = _takeover(rules).model_dump_json()
    assert _takeover(rules).model_dump_json() == first
    alerts, context = _detect(TAKEOVER, rules)
    alerts.reverse()
    with _offline() as enricher:
        again = build_incidents(alerts, rules, context=context, enricher=enricher)
    assert again[0].model_dump_json() == first


def test_without_events_or_enrichment() -> None:
    incidents = build_incidents(
        [alert("R-A", entities={"source.ip": "203.0.113.7"}, severity=Severity.MEDIUM)]
    )
    incident = incidents[0]
    assert incident.timeline[0].alert_id == incident.alerts[0].id
    assert len(incident.timeline) == 1
    assert incident.limitations == (
        "Enrichment not run: IP reputation and location were not considered",
        "Matched events were not available: no timeline, novelty or log-source checks",
    )
    assert incident.confidence is Confidence.LOW
    assert incident.recommended_actions == ()
    assert incident.indicators[0].enrichment == ()


def test_no_history_is_a_limitation_not_points(rules: list[CompiledRule]) -> None:
    context = EventContext()
    signin = event(at(0), "auth.signin.success", user_id="u-9", client="web")
    change = event(at(1), "account.password.changed", user_id="u-9")
    for e in (signin, change):
        context.add(e)
    incident = build_incidents(
        [alert("PRH-ACCT-001", [signin, change], entities={"user.id": "u-9"})],
        rules,
        context=context,
    )[0]
    assert not any("not seen" in c.reason for c in incident.score_breakdown)
    assert (
        "No earlier sign-in to u-9 in the input: could not tell whether 203.0.113.7 is new for it"
        in incident.limitations
    )


def test_missing_events_and_several_log_sources() -> None:
    context = EventContext()
    web = event(at(0), "web.request", log_source="access_log", method="GET", path="/x", status=404)
    app = event(at(1), user_id="u-1")
    for e in (web, app):
        context.add(e)
    gone = event(at(2))
    incident = build_incidents(
        [
            alert("R-A", [web, gone], entities={"source.ip": "203.0.113.7"}),
            alert("R-B", [app], entities={"source.ip": "203.0.113.7"}, severity=Severity.LOW),
        ],
        context=context,
    )[0]
    assert "1 matched event(s) were no longer in memory; the timeline is incomplete" in (
        incident.limitations
    )
    assert not any(x.startswith("Single log source") for x in incident.limitations)
    described = [e.description for e in incident.timeline if e.event_id == web.id]
    assert described == ["[access_log] web.request, from 203.0.113.7, GET /x -> 404"]


def test_timeline_keeps_the_earliest_and_latest_events() -> None:
    context = EventContext()
    events = [event(at(0, seconds=n)) for n in range(30)]
    for e in events:
        context.add(e)
    settings = IncidentSettings(max_timeline_events=10)
    incident = build_incidents(
        [alert("R-A", events, entities={"source.ip": "203.0.113.7"})],
        context=context,
        settings=settings,
    )[0]
    shown = [e.event_id for e in incident.timeline if e.event_id]
    assert shown == [e.id for e in events[:5] + events[-5:]]
    assert "The timeline shows 10 of 30 matched events (the earliest and the latest)" in (
        incident.limitations
    )


def test_lookup_limit_and_unparseable_ips() -> None:
    alerts = [
        alert(f"R-{n}", start=at(n * 60), entities={"source.ip": f"203.0.113.{n}"})
        for n in range(3)
    ]
    alerts.append(alert("R-X", start=at(500), entities={"source.ip": "not-an-ip"}))
    settings = IncidentSettings(max_lookups=2)
    with _offline() as enricher:
        incidents = build_incidents(alerts, enricher=enricher, settings=settings)
    assert len(incidents) == 4
    assert "Not enriched (limit of 2 addresses per run): 203.0.113.2" in incidents[2].limitations
    assert incidents[3].indicators[0].value == "not-an-ip"
    assert incidents[3].indicators[0].enrichment == ()


def test_provider_notes_and_setup_notes_become_limitations() -> None:
    online = build_enricher(EnrichSettings.load(env_file=None), offline=False)  # no providers
    with online as enricher:
        incident = build_incidents(
            [alert("R-A", entities={"source.ip": "203.0.113.7"})], enricher=enricher
        )[0]
    assert incident.limitations[0].startswith("Enrichment: no providers configured")


def test_shared_ip_and_unverified_tags_are_limitations() -> None:
    alerts = [
        alert(
            f"R-{n}",
            start=at(n),
            entities={"source.ip": "192.0.2.1", "user.id": f"u-{n}"},
            tags=("attack.t9999",),
        )
        for n in range(3)
    ]
    incidents = build_incidents(alerts, settings=IncidentSettings(max_ip_fanout=1))
    assert len(incidents) == 3
    assert (
        "192.0.2.1 was seen with 2 accounts and is treated as shared (NAT, proxy or VPN): "
        "it does not link further alerts"
    ) in incidents[0].limitations
    assert (
        f"ATT&CK tag attack.t9999 is not in the verified ATT&CK v{ATTACK_VERSION} list"
        in incidents[0].limitations
    )


def test_limits_on_entities_actions_and_limitations(rules: list[CompiledRule]) -> None:
    settings = IncidentSettings(max_entity_values=1, max_actions=2, max_limitations=3)
    alerts, context = _detect(TAKEOVER, rules)
    incident = IncidentBuilder(rules, context=context, settings=settings).build(alerts)[0]
    assert all(len(v) <= 1 for v in incident.entities.values())
    assert len(incident.recommended_actions) == 2
    assert len(incident.limitations) == 3


def test_incidents_are_sorted_by_time() -> None:
    late = alert("R-A", start=at(100), entities={"source.ip": "192.0.2.1"})
    early = alert("R-B", start=at(0), entities={"source.ip": "192.0.2.2"})
    assert [i.alerts[0].detector_id for i in build_incidents([late, early])] == ["R-B", "R-A"]
