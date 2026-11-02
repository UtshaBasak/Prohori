"""The payload sent to an LLM: redacted, no log content, size-capped, leak-checked."""

import json

import pytest

from prohori.llm import payload as payload_module
from prohori.llm.explain import explain
from prohori.llm.payload import RedactionError, build_payload, estimate_tokens
from prohori.llm.provider import MockProvider
from tests.unit.llm.conftest import BANGLA_USER, EMAIL, RAW, USER, personal_incident


def test_what_reaches_the_provider_has_no_accounts_emails_or_log_lines() -> None:
    incident = personal_incident()
    provider = MockProvider()
    result = explain(incident, provider, payload=build_payload(incident, mask_ips=True))
    assert len(provider.requests) == 1
    sent = provider.requests[0].system + provider.requests[0].prompt
    for value in (USER, BANGLA_USER, EMAIL, RAW, "u-2001", "203.0.113.7", "ua=Mozilla"):
        assert value not in sent, value
    assert "[user:" in sent
    assert "[ip:" in sent
    # Locally, the answer shows the real account again.
    assert USER in result.text
    assert "[user:" not in result.text


def test_the_payload_is_an_allow_list() -> None:
    payload = build_payload(personal_incident())
    data = json.loads(payload.text)
    assert data["format"] == "prohori.llm-payload/1"
    assert set(data) == {
        "format", "id", "title", "severity", "confidence", "score", "score_breakdown",
        "first_seen", "last_seen", "entities", "attack", "alerts", "timeline", "indicators",
        "recommended_actions", "limitations",
    }  # fmt: skip
    assert data["timeline"]["events"] > 0
    assert all(set(e) == {"time", "entry"} for e in data["timeline"]["alert_entries"])
    assert "provenance" not in payload.text
    # IP addresses are sent unless masked.
    assert "203.0.113.7" in payload.text
    assert BANGLA_USER not in payload.text  # non-ASCII text is written as is, then checked


def test_long_text_is_capped_and_big_incidents_are_trimmed() -> None:
    incident = personal_incident()
    payload = build_payload(incident, max_input_tokens=500)
    assert payload.trimmed
    assert json.loads(payload.text)["trimmed"] == list(payload.trimmed)
    assert payload.estimated_tokens == estimate_tokens(payload.text)
    assert len(build_payload(incident).data["title"]) <= payload_module.MAX_TEXT
    many = incident.model_copy(
        update={
            "alerts": incident.alerts * 8,
            "indicators": incident.indicators * 8,
            "title": "x" * 1000,
        }
    )
    trimmed = build_payload(many, max_input_tokens=500)
    data = trimmed.data
    assert len(data["alerts"]) == 20
    assert len(data["indicators"]) == 5
    assert data["title"].endswith("…")


def test_nothing_is_sent_when_a_value_would_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(payload_module, "find_leaks", lambda text, values: ["leak"])
    with pytest.raises(RedactionError, match="would still be sent"):
        build_payload(personal_incident())


def test_restore_replaces_exact_pseudonyms_only() -> None:
    payload = build_payload(personal_incident())
    pseudonym = next(p for p, original in payload.pseudonyms.items() if original == USER)
    assert payload.restore(f"see {pseudonym} and [user:0000000000]") == (
        f"see {USER} and [user:0000000000]"
    )
    empty = payload_module.Payload(data={}, text="", pseudonyms={}, trimmed=())
    assert empty.restore("unchanged") == "unchanged"
