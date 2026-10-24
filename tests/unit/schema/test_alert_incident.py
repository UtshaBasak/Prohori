"""Tests for the Alert and Incident models."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from pydantic import ValidationError

from prohori.schema import (
    Alert,
    Confidence,
    DetectorKind,
    Incident,
    IncidentStatus,
    Severity,
    alert_id,
)

T0 = datetime(2026, 10, 24, 13, 0, tzinfo=UTC)
T1 = T0 + timedelta(minutes=4)


def make_alert(**overrides: Any) -> Alert:
    data: dict[str, Any] = {
        "detector_id": "PRH-AUTH-001",
        "title": "Brute-force sign-in attempts from one IP",
        "severity": "high",
        "event_ids": ["evt-b", "evt-a"],
        "entities": {"source.ip": "203.0.113.7"},
        "first_seen": T0,
        "last_seen": T1,
        "attack": ["attack.credential_access", "attack.t1110"],
    }
    data.update(overrides)
    return Alert.model_validate(data)


def make_incident(**overrides: Any) -> Incident:
    data: dict[str, Any] = {
        "id": "INC-0001",
        "title": "Brute force against sign-in",
        "severity": "high",
        "score": 55.0,
        "score_breakdown": [
            {"reason": "rule severity high", "points": 40},
            {"reason": "two distinct rules", "points": 15},
        ],
        "first_seen": T0,
        "last_seen": T1,
        "entities": {"source.ip": ["203.0.113.7"]},
        "alerts": [make_alert()],
        "indicators": [
            {
                "type": "ip",
                "value": "203.0.113.7",
                "enrichment": [
                    {
                        "provider": "offline",
                        "retrieved_at": T1,
                        "data": {"country": "ZZ", "abuse_score": 90},
                    }
                ],
            }
        ],
        "timeline": [{"timestamp": T0, "description": "First failure", "event_id": "evt-a"}],
    }
    data.update(overrides)
    return Incident.model_validate(data)


class TestAlert:
    def test_defaults(self) -> None:
        alert = make_alert()
        assert alert.detector_kind is DetectorKind.RULE
        assert alert.severity is Severity.HIGH
        assert alert.score == 0.0

    def test_id_independent_of_event_order(self) -> None:
        assert make_alert().id == make_alert(event_ids=["evt-a", "evt-b"]).id
        assert make_alert().id == alert_id("PRH-AUTH-001", ["evt-a", "evt-b"])

    def test_model_alert(self) -> None:
        alert = make_alert(detector_id="iforest-logs", detector_kind="model", score=87.5)
        assert alert.detector_kind is DetectorKind.MODEL

    def test_requires_events(self) -> None:
        with pytest.raises(ValidationError):
            make_alert(event_ids=[])

    def test_time_range_order(self) -> None:
        with pytest.raises(ValidationError, match="last_seen"):
            make_alert(first_seen=T1, last_seen=T0)

    @pytest.mark.parametrize("score", [-1.0, 100.1, float("nan"), float("inf")])
    def test_score_bounds(self, score: float) -> None:
        with pytest.raises(ValidationError):
            make_alert(score=score)

    @pytest.mark.parametrize("tag", ["attack.t1110.003", "attack.initial_access", "attack.t1078"])
    def test_valid_attack_tags(self, tag: str) -> None:
        assert make_alert(attack=[tag]).attack == (tag,)

    @pytest.mark.parametrize("tag", ["t1110", "attack.T1110", "attack.t111", "attack.t1110.3"])
    def test_invalid_attack_tags(self, tag: str) -> None:
        with pytest.raises(ValidationError):
            make_alert(attack=[tag])

    def test_round_trip(self) -> None:
        alert = make_alert()
        assert Alert.model_validate_json(alert.model_dump_json()) == alert


class TestIncident:
    def test_defaults(self) -> None:
        incident = make_incident()
        assert incident.status is IncidentStatus.OPEN
        assert incident.confidence is Confidence.MEDIUM
        assert incident.limitations == ()

    def test_breakdown_must_sum_to_score(self) -> None:
        with pytest.raises(ValidationError, match="score_breakdown"):
            make_incident(score=60.0)

    def test_score_without_breakdown_allowed(self) -> None:
        assert make_incident(score=12.5, score_breakdown=[]).score == 12.5

    def test_requires_alerts(self) -> None:
        with pytest.raises(ValidationError):
            make_incident(alerts=[])

    @pytest.mark.parametrize("bad_id", ["0001", "inc-1", "INC-", "INC 1"])
    def test_id_format(self, bad_id: str) -> None:
        with pytest.raises(ValidationError):
            make_incident(id=bad_id)

    def test_time_range_order(self) -> None:
        with pytest.raises(ValidationError, match="last_seen"):
            make_incident(first_seen=T1, last_seen=T0)

    def test_round_trip(self) -> None:
        incident = make_incident(limitations=["single log source", "enrichment offline"])
        assert Incident.model_validate_json(incident.model_dump_json()) == incident


def test_severity_rank_orders_scale() -> None:
    ranks = [s.rank for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
    assert ranks == sorted(ranks) == [1, 2, 3, 4]
