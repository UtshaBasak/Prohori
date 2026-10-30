"""Track B: per-IP window features, the anomaly detectors and their alerts."""

import math
from datetime import UTC, datetime, timedelta

import pytest

from prohori.ml import anomaly
from prohori.ml.features import (
    FEATURES,
    MAX_WINDOW_EVENT_IDS,
    FeatureExtractor,
    Window,
    entropy,
    extract,
)
from prohori.schema import DetectorKind, Event, Severity
from prohori.schema.event import EventInfo, HttpInfo, SourceInfo, UserInfo
from prohori.schema.types import EventCategory, Outcome

T0 = datetime(2026, 10, 24, 12, 0, tzinfo=UTC)
_counter = iter(range(10**9))


def _event(
    seconds: float,
    ip: str | None = "198.51.100.7",
    *,
    action: str = "auth.signin.failure",
    category: EventCategory = EventCategory.AUTHENTICATION,
    outcome: Outcome = Outcome.FAILURE,
    user: str | None = "alice",
    path: str | None = None,
    status: int | None = None,
    agent: str | None = None,
) -> Event:
    return Event(
        timestamp=T0 + timedelta(seconds=seconds),
        log_source="app",
        event=EventInfo(action=action, category=category, outcome=outcome),
        source=SourceInfo(ip=ip),
        user=UserInfo(name=user),
        http=HttpInfo(path=path, status=status),
        user_agent=agent,
        raw=f"line {next(_counter)}",
    )


def _web(seconds: float, ip: str, path: str, status: int, agent: str = "Mozilla") -> Event:
    return _event(
        seconds,
        ip,
        action="web.request",
        category=EventCategory.WEB,
        outcome=Outcome.SUCCESS,
        user=None,
        path=path,
        status=status,
        agent=agent,
    )


# --------------------------------------------------------------------------- features


def test_windows_are_per_ip_and_five_minutes() -> None:
    events = [_event(0), _event(299), _event(300), _event(10, "203.0.113.9"), _event(5, None)]
    extractor = FeatureExtractor()
    passed = list(extractor.observe_all(events))
    assert passed == events
    windows = extractor.windows()
    assert [(w.ip, w.start.minute, int(w.features["events"])) for w in windows] == [
        ("198.51.100.7", 0, 2),
        ("203.0.113.9", 0, 1),
        ("198.51.100.7", 5, 1),
    ]
    assert extractor.skipped == 1
    assert set(windows[0].features) == set(FEATURES)
    assert windows[0].first_seen == T0
    assert windows[0].last_seen == T0 + timedelta(seconds=299)
    with pytest.raises(ValueError, match="positive"):
        FeatureExtractor(window=timedelta(0))


def test_ratios_need_enough_events() -> None:
    one = extract([_event(0)])[0].features
    assert one["auth_failures"] == 1
    assert one["failure_ratio"] == 0  # one failed sign-in is not a 100 % failure ratio
    many = extract(
        [_event(i) for i in range(4)]
        + [_event(10, outcome=Outcome.SUCCESS, action="auth.signin.success")]
    )[0].features
    assert many["auth_attempts"] == 5
    assert many["failure_ratio"] == pytest.approx(0.8)
    assert many["rate_per_minute"] == 1


def test_web_features() -> None:
    events = [
        _web(i, "192.0.2.4", f"/p{i % 4}", 404 if i % 2 else 200, f"ua{i % 3}") for i in range(8)
    ]
    features = extract(events)[0].features
    assert features["http_requests"] == 8
    assert features["distinct_paths"] == 4
    assert features["http_4xx_ratio"] == 0.5
    assert features["path_entropy"] == pytest.approx(2.0)
    assert features["distinct_user_agents"] == 3
    assert features["distinct_users"] == 0
    assert entropy([]) == 0
    assert entropy([5]) == 0


def test_new_clients_and_night() -> None:
    late = datetime(2026, 10, 24, 23, 0, tzinfo=UTC) - T0
    base = late.total_seconds()
    events = [
        _event(base + i, user=f"u{i}", agent="curl", outcome=Outcome.SUCCESS) for i in range(5)
    ] + [_event(base + 10 + i, user="u0", agent="curl", outcome=Outcome.SUCCESS) for i in range(5)]
    features = extract(events)[0].features
    assert features["new_client_ratio"] == 0.5  # u0+curl seen once, then repeated
    assert features["night_ratio"] == 1
    # The same hour in Dhaka (UTC+6) is 05:00: still night; noon UTC is not.
    assert extract(events, timezone="Asia/Dhaka")[0].features["night_ratio"] == 1
    assert extract([_event(i) for i in range(5)])[0].features["night_ratio"] == 0


def test_event_ids_are_capped() -> None:
    window = extract([_event(i / 10) for i in range(MAX_WINDOW_EVENT_IDS + 50)])[0]
    assert len(window.event_ids) == MAX_WINDOW_EVENT_IDS
    assert window.features["events"] == MAX_WINDOW_EVENT_IDS + 50


# --------------------------------------------------------------------------- detectors


def _windows(n: int = 30, *, spike: dict[str, float] | None = None) -> list[Window]:
    """``n`` ordinary windows (one failed sign-in now and then) and optionally one spike."""
    windows = []
    for i in range(n):
        features = dict.fromkeys(FEATURES, 0.0)
        features["events"] = features["auth_attempts"] = 1.0 + i % 2
        features["auth_failures"] = float(i % 3 == 0)
        features["distinct_users"] = 1.0
        windows.append(Window(f"192.0.2.{i}", T0, T0, T0, (f"e{i}",), features))
    if spike is not None:
        features = dict.fromkeys(FEATURES, 0.0) | {"events": 1.0, "distinct_users": 1.0} | spike
        windows.append(Window("203.0.113.66", T0, T0, T0 + timedelta(minutes=4), ("x",), features))
    return windows


def test_zscore_floors_and_spikes() -> None:
    quiet = anomaly.zscore(_windows())
    assert max(s.score for s in quiet) < anomaly.Z_THRESHOLD  # occasional failures are usual
    spiked = anomaly.zscore(_windows(spike={"auth_failures": 40.0, "auth_attempts": 40.0}))
    top = max(spiked, key=lambda s: s.score)
    assert top.window.ip == "203.0.113.66"
    assert top.score == pytest.approx(40.0)  # floor of 1 failure; the median is 0
    assert top.reasons[0][0] in {"auth_failures", "auth_attempts"}
    # Lower than usual is never anomalous.
    low = anomaly.zscore(_windows(spike={"events": 0.0, "distinct_users": 0.0}))
    assert max(s.score for s in low) < 2
    assert anomaly.zscore(_windows(5)) == []  # too few windows to judge


def test_threshold_baseline() -> None:
    scored = anomaly.threshold(_windows(spike={"auth_failures": 12.0, "distinct_users": 6.0}))
    assert scored[-1].score == 2
    assert {r[0] for r in scored[-1].reasons} == {"auth_failures", "distinct_users"}
    assert scored[0].score == 0


def test_iforest_is_seeded() -> None:
    windows = _windows(spike={"auth_failures": 40.0, "distinct_users": 25.0})
    first = anomaly.iforest(windows, seed=1)
    again = anomaly.iforest(windows, seed=1)
    assert [s.score for s in first] == [s.score for s in again]
    top = max(first, key=lambda s: s.score)
    assert top.window.ip == "203.0.113.66"
    assert 0.5 < top.score <= 1
    assert anomaly.iforest(_windows(5)) == []


def test_alerts_are_model_alerts_with_numbers_only() -> None:
    windows = _windows(spike={"auth_failures": 40.0, "distinct_users": 25.0})
    alerts = anomaly.detect(windows, ["zscore", "iforest"])
    assert {a.detector_id for a in alerts} == {anomaly.ZSCORE_ID, anomaly.IFOREST_ID}
    for alert in alerts:
        assert alert.detector_kind is DetectorKind.MODEL
        assert alert.severity is Severity.LOW
        assert alert.entities == {"source.ip": "203.0.113.66"}
        assert alert.event_ids == ("x",)
        assert 0 < alert.score <= 100
        assert "203.0.113" not in alert.explanation
        assert "alice" not in alert.title + alert.explanation
    zscore = next(a for a in alerts if a.detector_id == anomaly.ZSCORE_ID)
    assert zscore.explanation.startswith("z 40: ")
    assert "auth_failures 40 (usual 0)" in zscore.explanation
    # A stricter cut-off removes the alert; an unknown detector is an error.
    assert anomaly.detect(windows, ["zscore"], cutoffs={"zscore": 100.0}) == []
    with pytest.raises(ValueError, match="unknown detector"):
        anomaly.detect(windows, ["lof"])
    threshold = anomaly.detect(windows, ["threshold"])[0]
    assert "(limit 10)" in threshold.explanation


def test_nan_scores_are_never_flagged() -> None:
    window = _windows(1)[0]
    scored = [anomaly.Scored(window, math.nan, ()), anomaly.Scored(window, 9.0, ())]
    assert [s.score for s in anomaly.flagged(scored, 5.0)] == [9.0]
