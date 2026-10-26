"""Redaction: no account name, id, email or (optionally) IP survives in any format."""

import html
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from prohori.enrich import EnrichSettings, build_enricher
from prohori.incidents import EventContext, IncidentSettings, build_incidents
from prohori.parsers import detect_format, get_parser, iter_text_lines
from prohori.reports import Redactor, ReportFormat, find_leaks, render
from prohori.reports.redact import is_pseudonym
from prohori.rules import RuleEngine, builtin_rules_dir, load_rules
from prohori.schema import Event, Incident
from tests.unit.enrich.conftest import isolated_settings, no_network
from tests.unit.incidents.factories import alert, at, event
from tests.unit.reports.conftest import ROOT

__all__ = ["isolated_settings", "no_network"]  # autouse: no network, no real cache

KEY = b"test-key-for-redaction-0123456789"
SAMPLES = ["auth.log", "access.log", "app-security.jsonl", "account-takeover.jsonl"]


def _pipeline(name: str) -> tuple[list[Incident], list[Event]]:
    lines = (ROOT / "samples" / "logs" / name).read_text(encoding="utf-8").splitlines()
    fmt = detect_format(list(iter_text_lines(lines)))
    assert fmt is not None
    options = {"year": 2026} if fmt == "auth_log" else {}
    events = list(get_parser(fmt, **options).parse(iter_text_lines(lines), source=name))
    rules = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
    context = EventContext()
    engine = RuleEngine(rules, reference_time=datetime(2026, 10, 27, tzinfo=UTC))
    alerts = list(engine.run(context.observe(events)))
    with build_enricher(EnrichSettings.load(env_file=None), offline=True) as enricher:
        return build_incidents(alerts, rules, context=context, enricher=enricher), events


@pytest.mark.parametrize("sample", SAMPLES)
@pytest.mark.parametrize("fmt", list(ReportFormat))
def test_no_personal_value_from_the_source_events_survives(sample: str, fmt: ReportFormat) -> None:
    """Checked against the parsed events, not the incident, so nothing it hides is missed."""
    incidents, events = _pipeline(sample)
    assert incidents
    personal = {
        value
        for e in events
        for value in (e.user.name, e.user.id, e.user.email_hash, e.source.ip and str(e.source.ip))
        if value
    }
    for incident in incidents:
        redacted = Redactor(KEY, ips=True).redact(incident)
        text = render(redacted, fmt)
        if fmt is ReportFormat.HTML:  # check the shown text, not the page's CSS and tags
            text = html.unescape(
                re.sub(r"<[^>]+>", " ", re.sub(r"(?s)<style>.*?</style>", "", text))
            )
        text += redacted.model_dump_json()
        assert find_leaks(text, personal) == [], (sample, fmt)


def test_auth_log_usernames_from_the_timeline_are_redacted() -> None:
    incidents, events = _pipeline("auth.log")
    names = {e.user.name for e in events if e.user.name}
    timeline_accounts = {t.account for i in incidents for t in i.timeline if t.account}
    assert timeline_accounts & names  # the case that entities alone would miss
    for incident in incidents:
        redacted = Redactor(KEY).redact(incident)
        assert find_leaks(redacted.model_dump_json(), names) == []
        # Without --redact-ips the addresses stay.
        assert "203.0.113.7" in redacted.model_dump_json()


def test_action_names_and_rule_ids_are_not_corrupted() -> None:
    granted = event(at(0), "admin.role.granted", user_name="admin")
    incident = build_incidents(
        [alert("PRH-ADMIN-001", [granted], entities={"user.name": "admin"}, title="admin changed")],
        context=_context(granted),
    )[0]
    redacted = Redactor(KEY).redact(incident)
    text = redacted.model_dump_json()
    assert "admin.role.granted" in text
    assert "PRH-ADMIN-001" in text
    pseudonym = Redactor(KEY).pseudonym("user", "admin")
    assert f"account {pseudonym}" in redacted.timeline[0].description
    assert redacted.title.startswith(pseudonym)  # prose may change; identifiers may not


def _context(*events: Event) -> EventContext:
    context = EventContext()
    for e in events:
        context.add(e)
    return context


def test_pseudonyms_are_stable_keyed_and_never_leak_the_key() -> None:
    a = Redactor(KEY)
    assert a.pseudonym("user", "u-1") == Redactor(KEY).pseudonym("user", "u-1")
    assert a.pseudonym("user", "u-1") != Redactor(b"another-key-0123456789").pseudonym(
        "user", "u-1"
    )
    assert a.pseudonym("user", "u-1") != a.pseudonym("ip", "u-1")
    assert is_pseudonym(a.pseudonym("email", "x@example.com"))
    incident = build_incidents([alert("R-A", entities={"user.id": "u-1"})])[0]
    assert KEY.decode() not in render(a.redact(incident), ReportFormat.JSON)


def test_short_keys_are_rejected() -> None:
    with pytest.raises(ValueError, match="16 bytes"):
        Redactor(b"short")


def test_emails_in_free_text_are_redacted() -> None:
    incident = build_incidents(
        [alert("R-A", title="Reset for alice@example.com requested", entities={"user.id": "u-1"})]
    )[0]
    redacted = Redactor(KEY).redact(incident)
    assert "alice@example.com" not in redacted.model_dump_json()
    assert Redactor(KEY).pseudonym("email", "alice@example.com") in redacted.title


def test_a_value_inside_a_pseudonym_is_not_replaced_again() -> None:
    incident = build_incidents([alert("R-A", entities={"user.name": "user", "user.id": "ip"})])[0]
    redactor = Redactor(KEY)
    text = redactor.redact(incident).model_dump_json()
    assert find_leaks(text, redactor.replaced) == []
    for pseudonym in redactor.replaced.values():
        assert pseudonym in text


def test_ips_in_free_text_and_networks() -> None:
    incident = build_incidents(
        [
            alert(
                "R-A",
                title="Seen from 198.51.100.9 and 2001:db8::5 in 203.0.113.0/24",
                entities={"source.ip": "203.0.113.7"},
            )
        ]
    )[0]
    redacted = Redactor(KEY, ips=True).redact(incident).model_dump_json()
    for ip in ("198.51.100.9", "2001:db8::5", "203.0.113.0", "203.0.113.7"):
        assert ip not in redacted
    assert "1.2.3" not in Redactor(KEY, ips=True).redact(incident).title  # version-like text kept


def test_nothing_to_redact_returns_the_incident() -> None:
    incident = build_incidents([alert("R-A")])[0]
    assert Redactor(KEY).redact(incident) is incident


def test_find_leaks() -> None:
    assert find_leaks("account root.", ["root"]) == ["root"]
    assert find_leaks("rootkit admin.role.granted", ["root", "admin"]) == []
    assert find_leaks("[user:0123456789] ok", ["user"]) == []
    assert find_leaks("anything", []) == []


def test_sample_directory_has_one_incident() -> None:
    assert len(list(Path(ROOT / "samples" / "incidents").glob("INC-*.json"))) == 1


def test_account_named_only_in_novelty_text_is_redacted() -> None:
    """A success cut from a long timeline is still named in limitations; it must be redacted."""
    before = [event(at(0, seconds=n), "ssh.login.failure", user_name=f"guess{n}") for n in range(6)]
    success = event(at(1), "ssh.login.success", user_name="deploy")
    after = [event(at(2, seconds=n), "ssh.login.failure", user_name=f"late{n}") for n in range(6)]
    events = [*before, success, *after]
    incident = build_incidents(
        [alert("PRH-AUTH-003", events, entities={"source.ip": "203.0.113.7"})],
        context=_context(*events),
        settings=IncidentSettings(max_timeline_events=2),
    )[0]
    assert "deploy" not in {t.account for t in incident.timeline}
    assert any("deploy" in x for x in incident.limitations)  # named by the novelty check
    redacted = Redactor(KEY).redact(incident)
    assert "deploy" not in redacted.model_dump_json()
