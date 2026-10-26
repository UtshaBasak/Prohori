"""The incident points system."""

import math
from datetime import UTC, datetime

import pytest
from hypothesis import given
from hypothesis import strategies as st
from tests.unit.incidents.factories import alert, at, event

from prohori.incidents import EventSummary, Novelty, NoveltyStatus, score_incident, scoring
from prohori.incidents.scoring import reputation, success_after_failure
from prohori.schema import EnrichmentResult, Severity

RETRIEVED = datetime(2026, 10, 1, tzinfo=UTC)


def _result(provider: str = "abuseipdb", /, **data: object) -> EnrichmentResult:
    return EnrichmentResult.model_validate(
        {"provider": provider, "retrieved_at": RETRIEVED, "data": data}
    )


def _summary(*args: object, **kwargs: object) -> EventSummary:
    return EventSummary.from_event(event(*args, **kwargs))  # type: ignore[arg-type]


def _reasons(score: scoring.Score) -> dict[str, float]:
    return {c.reason: c.points for c in score.components}


def test_single_alert_scores_its_severity() -> None:
    score = score_incident([alert("R-A", severity=Severity.MEDIUM)], [], [], {}, [])
    assert score.total == scoring.SEVERITY_POINTS[Severity.MEDIUM]
    assert score.severity is Severity.MEDIUM
    assert len(score.components) == 1


def test_extra_rules_add_points_up_to_a_cap() -> None:
    alerts = [alert(f"R-{n}", severity=Severity.LOW) for n in range(6)]
    alerts.append(alert("R-0", severity=Severity.LOW))  # a repeat of a rule adds nothing
    score = score_incident(alerts, [], [], {}, [])
    assert score.total == scoring.SEVERITY_POINTS[Severity.LOW] + scoring.EXTRA_RULE_CAP


def test_success_after_failure_from_events() -> None:
    failure = _summary(at(0), user_id="u-1")
    success = _summary(at(1), "auth.signin.success", user_id="u-1", ip="198.51.100.9")
    assert success_after_failure([], [failure, success])  # same account, other IP
    assert not success_after_failure([], [success])
    early_success = _summary(at(-1), "auth.signin.success", user_id="u-2", ip="192.0.2.1")
    assert not success_after_failure([], [early_success, failure])
    assert success_after_failure(["PRH-AUTH-003"], [])


def test_sensitive_actions_from_events_or_rules() -> None:
    change = _summary(at(0), "account.2fa.disabled", user_id="u-1")
    by_event = score_incident([alert("R-A")], [change], [], {}, [])
    assert "Sensitive account or admin change: account.2fa.disabled" in _reasons(by_event)
    by_rule = score_incident([alert("PRH-ADMIN-001")], [], [], {}, [])
    assert "Sensitive account or admin change: PRH-ADMIN-001" in _reasons(by_rule)


@pytest.mark.parametrize(
    ("data", "points"),
    [
        ({"abuse_score": 97}, 15),
        ({"abuse_score": 74}, 8),
        ({"abuse_score": 24}, 0),
        ({"malicious": 3}, 15),
        ({"malicious": 1}, 8),
        ({"malicious": 0}, 0),
        ({"is_tor": True}, 5),
        ({"abuse_score": 30, "is_tor": True}, 13),
        ({"abuse_score": 97, "malicious": 9, "is_tor": True}, 20),  # capped
        ({"abuse_score": True}, 0),  # booleans are not numbers
        ({"country": "NL"}, 0),
    ],
)
def test_reputation_points(data: dict[str, object], points: int) -> None:
    assert reputation("203.0.113.7", [_result(**data)])[0] == points


def test_reputation_reason_names_the_evidence_and_sources() -> None:
    points, reason = reputation(
        "203.0.113.7", [_result("virustotal", malicious=1), _result("offline", abuse_score=30)]
    )
    assert points == 8 + 8
    assert reason == (
        "Reputation of 203.0.113.7: abuse confidence 30; 1 vendor flags it as malicious "
        "(from bundled demo data, virustotal)"
    )


def test_worst_ip_counts() -> None:
    enrichment = {
        "192.0.2.1": [_result(abuse_score=30)],
        "203.0.113.7": [_result(abuse_score=99)],
    }
    score = score_incident([alert("R-A", severity=Severity.LOW)], [], [], enrichment, [])
    assert score.reputation_points == 15
    assert any("203.0.113.7" in c.reason for c in score.components)


def test_spread_across_ips_and_accounts() -> None:
    keys = [
        ("source.ip", "192.0.2.1"),
        ("source.ip", "192.0.2.2"),
        ("user.id", "u-1"),
        ("user.id", "u-2"),
        ("user.email_hash", "h-1"),
    ]
    score = score_incident([alert("R-A", severity=Severity.LOW)], [], keys, {}, [])
    assert _reasons(score)["Spread: 2 source IPs, 2 accounts"] == 10
    many = [("source.ip", f"192.0.2.{n}") for n in range(10)]
    capped = score_incident([alert("R-A", severity=Severity.LOW)], [], many, {}, [])
    assert capped.total == scoring.SEVERITY_POINTS[Severity.LOW] + scoring.SPREAD_CAP


def test_novelty_points_only_for_new_values() -> None:
    new = Novelty("u-1", "203.0.113.7", NoveltyStatus.NEW, "web", NoveltyStatus.NEW, 2)
    score = score_incident([alert("R-A", severity=Severity.LOW)], [], [], {}, [new])
    assert score.total == 10 + scoring.NEW_IP_POINTS + scoring.NEW_CLIENT_POINTS
    for status in (NoveltyStatus.KNOWN, NoveltyStatus.NO_HISTORY, NoveltyStatus.UNKNOWN):
        other = Novelty("u-1", "203.0.113.7", status, "web", status, 0)
        assert (
            score_incident([alert("R-A", severity=Severity.LOW)], [], [], {}, [other]).total == 10
        )


def test_score_is_capped_with_a_visible_component() -> None:
    alerts = [alert(f"R-{n}", severity=Severity.CRITICAL) for n in range(4)]
    enrichment = {"203.0.113.7": [_result(abuse_score=99, malicious=9)]}
    new = Novelty("u-1", "203.0.113.7", NoveltyStatus.NEW, "web", NoveltyStatus.NEW, 1)
    score = score_incident(alerts, [], [], enrichment, [new])
    assert score.total == scoring.MAX_SCORE
    assert score.components[-1].reason == "Capped at 100"
    assert score.components[-1].points < 0
    assert math.fsum(c.points for c in score.components) == score.total


@pytest.mark.parametrize(
    ("severity", "extra_rules", "expected"),
    [
        (Severity.LOW, 0, Severity.LOW),  # 10
        (Severity.LOW, 2, Severity.MEDIUM),  # 30
        (Severity.MEDIUM, 3, Severity.HIGH),  # 50
        (Severity.HIGH, 3, Severity.HIGH),  # 65
        (Severity.CRITICAL, 0, Severity.CRITICAL),  # 50, but never below the top alert
    ],
)
def test_severity_bands_with_alert_floor(
    severity: Severity, extra_rules: int, expected: Severity
) -> None:
    alerts = [alert("R-TOP", severity=severity)]
    alerts += [alert(f"R-{n}", severity=Severity.LOW) for n in range(extra_rules)]
    assert score_incident(alerts, [], [], {}, []).severity is expected


def test_critical_band() -> None:
    alerts = [alert("R-TOP"), *(alert(f"R-{n}", severity=Severity.LOW) for n in range(3))]
    score = score_incident(alerts, [], [], {}, [])
    assert score.total == 65
    with_success = score_incident(
        [*alerts, alert("PRH-AUTH-003", severity=Severity.LOW)], [], [], {}, []
    )
    assert with_success.total == 85
    assert with_success.severity is Severity.CRITICAL


@given(
    severities=st.lists(st.sampled_from(list(Severity)), min_size=1, max_size=8),
    abuse=st.none() | st.integers(0, 100),
    malicious=st.none() | st.integers(0, 80),
    tor=st.booleans(),
    ips=st.integers(1, 6),
    accounts=st.integers(0, 6),
    sensitive=st.booleans(),
)
def test_breakdown_always_sums_to_the_total(
    severities: list[Severity],
    abuse: int | None,
    malicious: int | None,
    tor: bool,
    ips: int,
    accounts: int,
    sensitive: bool,
) -> None:
    alerts = [alert(f"R-{n}", severity=s) for n, s in enumerate(severities)]
    data: dict[str, object] = {"is_tor": tor}
    if abuse is not None:
        data["abuse_score"] = abuse
    if malicious is not None:
        data["malicious"] = malicious
    keys = [("source.ip", f"192.0.2.{n}") for n in range(ips)]
    keys += [("user.id", f"u-{n}") for n in range(accounts)]
    events = [_summary(at(0), "account.bkash.changed", user_id="u-0")] if sensitive else []
    score = score_incident(alerts, events, keys, {"192.0.2.0": [_result(**data)]}, [])
    assert sum(c.points for c in score.components) == score.total
    assert 0 <= score.total <= scoring.MAX_SCORE
    assert score.severity.rank >= max(s.rank for s in severities)
