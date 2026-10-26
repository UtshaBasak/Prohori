"""Tests for the stateful rule engine."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from prohori.rules import CompiledRule, compile_rule
from prohori.rules.engine import MAX_ALERT_EVENT_IDS, RuleEngine
from prohori.schema import Alert, Event, event_id

T0 = datetime(2026, 10, 24, 13, 50, tzinfo=UTC)


def rule(detection: dict[str, Any], **meta: Any) -> CompiledRule:
    document = {
        "id": "TST-E-001",
        "title": "Engine test rule",
        "status": "test",
        "severity": "high",
        "tags": ["attack.t1110"],
        "detection": detection,
        **meta,
    }
    result = compile_rule(document)
    assert result.rule is not None, result.errors
    return result.rule


def ev(
    seconds: float,
    action: str = "auth.signin.failure",
    ip: str | None = "203.0.113.7",
    n: int = 0,
    **fields: Any,
) -> Event:
    ts = T0 + timedelta(seconds=seconds)
    raw = f"{action} {ip} {seconds} {n} {sorted(fields.items())}"
    data: dict[str, Any] = {
        "id": event_id("test", ts, raw),
        "timestamp": ts,
        "log_source": "test",
        "event": {"action": action, "category": "authentication"},
        "source": {"ip": ip},
        "raw": raw,
    }
    for key, value in fields.items():
        head, _, tail = key.partition("__")
        if tail:
            data.setdefault(head, {})[tail] = value
        else:
            data[head] = value
    return Event.model_validate(data)


def run(
    rules: list[CompiledRule], events: list[Event], **options: Any
) -> tuple[list[Alert], RuleEngine]:
    engine = RuleEngine(rules, **options)
    return list(engine.run(events)), engine


FAILURE = {"event.action": "auth.signin.failure"}
SUCCESS = {"event.action": "auth.signin.success"}


def count_rule(threshold: int = 3, window: str = "60s", mode: str = "sliding") -> CompiledRule:
    return rule(
        {
            "failure": FAILURE,
            "aggregate": {
                "group_by": ["source.ip"],
                "window": window,
                "mode": mode,
                "count_gte": threshold,
            },
            "condition": "failure and aggregate",
        }
    )


class TestStateless:
    def test_one_alert_per_matching_event_with_entities(self) -> None:
        plain = rule({"failure": FAILURE, "condition": "failure"})
        alerts, _ = run([plain], [ev(0, user__name="alice"), ev(1, action="auth.signin.success")])
        (alert,) = alerts
        assert alert.detector_id == "TST-E-001"
        assert alert.entities == {"source.ip": "203.0.113.7", "user.name": "alice"}
        assert alert.attack == ("attack.t1110",)
        assert alert.score == 75.0
        assert alert.first_seen == alert.last_seen == T0

    def test_logsource_filter(self) -> None:
        plain = rule({"failure": FAILURE, "condition": "failure"}, logsource={"category": "web"})
        assert run([plain], [ev(0)])[0] == []


class TestCountThreshold:
    def test_alert_when_threshold_reached(self) -> None:
        alerts, _ = run([count_rule()], [ev(0), ev(10), ev(20)])
        (alert,) = alerts
        assert alert.entities == {"source.ip": "203.0.113.7"}
        assert len(alert.event_ids) == 3
        assert (alert.first_seen, alert.last_seen) == (T0, T0 + timedelta(seconds=20))
        assert "3 matching events (threshold 3)" in alert.explanation

    def test_state_resets_after_alert(self) -> None:
        alerts, _ = run([count_rule()], [ev(i) for i in range(7)])
        assert len(alerts) == 2

    def test_window_edge_exactly_window_old_is_outside(self) -> None:
        assert run([count_rule()], [ev(0), ev(30), ev(60)])[0] == []

    def test_window_edge_just_inside(self) -> None:
        assert len(run([count_rule()], [ev(0), ev(30), ev(59.999)])[0]) == 1

    def test_groups_are_separate(self) -> None:
        events = [ev(0, ip="192.0.2.1"), ev(1, ip="192.0.2.2"), ev(2, ip="192.0.2.1")]
        assert run([count_rule()], events)[0] == []

    def test_missing_group_field_is_skipped_and_counted(self) -> None:
        alerts, engine = run([count_rule()], [ev(0, ip=None), ev(1, ip=None), ev(2, ip=None)])
        assert alerts == []
        assert engine.stats.ungrouped_events == 3

    def test_tumbling_windows_align_to_the_epoch(self) -> None:
        tumbling = count_rule(mode="tumbling")
        # T0 is 13:50:00, a minute boundary: 58s and 59s share a bucket, 60s starts the next.
        assert run([tumbling], [ev(58), ev(59), ev(60)])[0] == []
        assert len(run([tumbling], [ev(0), ev(30), ev(59)])[0]) == 1

    def test_event_ids_are_capped(self) -> None:
        big = count_rule(threshold=150, window="1h")
        (alert,) = run([big], [ev(i) for i in range(150)])[0]
        assert len(alert.event_ids) == MAX_ALERT_EVENT_IDS
        assert "showing the last 100 event ids" in alert.explanation


class TestDistinctAndRatio:
    def test_distinct_users(self) -> None:
        distinct = rule(
            {
                "failure": FAILURE,
                "aggregate": {
                    "group_by": ["source.ip"],
                    "window": "5m",
                    "distinct": {"field": "user.name", "gte": 3},
                },
                "condition": "failure and aggregate",
            }
        )
        same = [ev(i, user__name="alice", n=i) for i in range(10)]
        assert run([distinct], same)[0] == []
        varied = [ev(i, user__name=name) for i, name in enumerate(["a", "b", "a", "c"])]
        (alert,) = run([distinct], varied)[0]
        assert "3 distinct user.name values" in alert.explanation

    def test_ratio_with_minimum_count(self) -> None:
        ratio = rule(
            {
                "request": {"event.action|startswith": "auth."},
                "failure": FAILURE,
                "aggregate": {
                    "group_by": ["source.ip"],
                    "window": "1m",
                    "ratio": {"selection": "failure", "gte": 0.75, "min_count": 4},
                },
                "condition": "request and aggregate",
            }
        )
        three = [ev(0), ev(1), ev(2)]
        assert run([ratio], three)[0] == []
        mixed = [ev(0), ev(1), ev(2, action="auth.signin.success"), ev(3), ev(4)]
        (alert,) = run([ratio], mixed)[0]
        assert "3 of 4 events matched failure" in alert.explanation


def sequence_rule(within: str = "10m", first_count: int = 3) -> CompiledRule:
    return rule(
        {
            "failure": FAILURE,
            "success": SUCCESS,
            "sequence": {
                "by": ["source.ip"],
                "within": within,
                "steps": [
                    {"selection": "failure", "count_gte": first_count},
                    {"selection": "success"},
                ],
            },
            "condition": "sequence",
        }
    )


class TestSequence:
    def test_failures_then_success(self) -> None:
        events = [ev(0), ev(10), ev(20), ev(30, action="auth.signin.success")]
        (alert,) = run([sequence_rule()], events)[0]
        assert len(alert.event_ids) == 4
        assert alert.entities == {"source.ip": "203.0.113.7"}

    def test_success_first_does_not_count(self) -> None:
        events = [ev(0, action="auth.signin.success"), ev(10), ev(20), ev(30)]
        assert run([sequence_rule()], events)[0] == []

    def test_within_measured_from_first_counted_failure(self) -> None:
        late_success = [ev(0), ev(10), ev(20), ev(600, action="auth.signin.success")]
        assert run([sequence_rule()], late_success)[0] == []
        in_time = [ev(0), ev(10), ev(20), ev(599, action="auth.signin.success")]
        assert len(run([sequence_rule()], in_time)[0]) == 1

    def test_first_step_slides_over_old_failures(self) -> None:
        # Failures at 0 and 1 are older than 10m when the later ones arrive, so the start moves.
        events = [ev(0), ev(1), ev(700), ev(710), ev(720), ev(730, action="auth.signin.success")]
        (alert,) = run([sequence_rule()], events)[0]
        assert alert.first_seen == T0 + timedelta(seconds=700)

    def test_extra_failures_after_first_step_are_ignored(self) -> None:
        events = [ev(i) for i in range(6)] + [ev(10, action="auth.signin.success")]
        (alert,) = run([sequence_rule()], events)[0]
        assert len(alert.event_ids) == 4

    def test_expired_sequence_restarts_with_the_event(self) -> None:
        events = [
            ev(0),
            ev(1),
            ev(2),
            ev(700),
            ev(701),
            ev(702),
            ev(703, action="auth.signin.success"),
        ]
        (alert,) = run([sequence_rule()], events)[0]
        assert alert.first_seen == T0 + timedelta(seconds=700)

    def test_event_matching_two_steps_counts_for_the_current_step(self) -> None:
        both = rule(
            {
                "any_auth": {"event.action|startswith": "auth."},
                "success": SUCCESS,
                "sequence": {
                    "by": ["source.ip"],
                    "within": "10m",
                    "steps": [{"selection": "any_auth", "count_gte": 2}, {"selection": "success"}],
                },
                "condition": "sequence",
            }
        )
        events = [ev(0), ev(1), ev(2, action="auth.signin.success")]
        assert len(run([both], events)[0]) == 1

    def test_entities_are_separate(self) -> None:
        events = [ev(0), ev(1), ev(2), ev(3, action="auth.signin.success", ip="198.51.100.1")]
        assert run([sequence_rule()], events)[0] == []

    def test_later_final_step_events_raise_further_alerts(self) -> None:
        # Like a second account change after one sign-in: it must not be swallowed.
        events = [
            ev(0),
            ev(1),
            ev(2),
            ev(10, action="auth.signin.success"),
            ev(20),  # an earlier-step event after completion is ignored
            ev(30, action="auth.signin.success"),
        ]
        first, second = run([sequence_rule()], events)[0]
        assert first.event_ids[:3] == second.event_ids[:3]  # the same earlier steps
        assert first.event_ids[3] != second.event_ids[3]
        assert len(second.event_ids) == 4
        assert first.id != second.id

    def test_further_alerts_stop_when_the_window_ends(self) -> None:
        events = [
            ev(0),
            ev(1),
            ev(2),
            ev(10, action="auth.signin.success"),
            ev(599, action="auth.signin.success"),  # still within 10m of the start
            ev(600, action="auth.signin.success"),  # expired: starts over, needs failures again
        ]
        assert len(run([sequence_rule()], events)[0]) == 2

    def test_final_step_count_applies_to_further_alerts(self) -> None:
        twice = rule(
            {
                "failure": FAILURE,
                "success": SUCCESS,
                "sequence": {
                    "by": ["source.ip"],
                    "within": "10m",
                    "steps": [{"selection": "failure"}, {"selection": "success", "count_gte": 2}],
                },
                "condition": "sequence",
            }
        )
        successes = [ev(10 + i, action="auth.signin.success", n=i) for i in range(5)]
        alerts = run([twice], [ev(0), *successes])[0]
        assert [len(a.event_ids) for a in alerts] == [3, 3]  # after 2 and after 4 successes


class TestOrdering:
    def test_out_of_order_within_lateness(self) -> None:
        events = [ev(20), ev(0), ev(10)]
        alerts, engine = run([count_rule()], events, lateness=timedelta(seconds=30))
        assert len(alerts) == 1
        assert engine.stats.late_events == 0

    def test_ties_are_ordered_by_event_id_without_lateness(self) -> None:
        events = [ev(0, n=i) for i in range(3)]
        forward = [a.model_dump() for a in run([count_rule()], events)[0]]
        backward = [a.model_dump() for a in run([count_rule()], list(reversed(events)))[0]]
        assert forward == backward
        assert len(forward) == 1

    def test_event_beyond_lateness_is_dropped_and_counted(self) -> None:
        events = [ev(0), ev(100), ev(200), ev(10)]
        _, engine = run([count_rule()], events, lateness=timedelta(seconds=30))
        assert engine.stats.late_events == 1
        assert engine.stats.events_evaluated == 3

    def test_future_timestamp_does_not_stop_detection(self) -> None:
        events = [ev(0), ev(1), ev(2, n=1)]
        bogus = Event.model_validate(
            {
                "timestamp": datetime(2099, 1, 1, tzinfo=UTC),
                "log_source": "test",
                "event": {"action": "auth.signin.failure", "category": "authentication"},
                "source": {"ip": "203.0.113.7"},
                "raw": "bogus",
            }
        )
        stream = [events[0], bogus, events[1], events[2], ev(3), ev(4), ev(5)]
        alerts, engine = run([count_rule()], stream, reference_time=T0 + timedelta(hours=1))
        assert len(alerts) == 2
        assert engine.stats.future_events == 1
        assert engine.stats.late_events == 0

    def test_negative_lateness_rejected(self) -> None:
        with pytest.raises(ValueError, match="lateness"):
            RuleEngine([], lateness=timedelta(seconds=-1))

    def test_flush_is_idempotent(self) -> None:
        engine = RuleEngine([count_rule()], lateness=timedelta(minutes=5))
        for event in [ev(0), ev(1), ev(2)]:
            assert engine.process(event) == []
        assert len(engine.flush()) == 1
        assert engine.flush() == []
        assert engine.state_size()["buffered_events"] == 0


class TestBoundedState:
    def test_group_cap_and_evictions(self) -> None:
        engine = RuleEngine([count_rule(threshold=5, window="1h")], max_groups=1_000)
        for i in range(20_000):
            engine.process(ev(i * 0.001, ip=f"10.{i // 65536}.{i // 256 % 256}.{i % 256}"))
        engine.flush()
        assert engine.state_size()["rule_state"] <= 2 * 1_000
        assert engine.stats.groups_evicted == 19_000

    def test_state_drains_after_the_window(self) -> None:
        engine = RuleEngine([count_rule(threshold=50, window="60s")])
        for i in range(2_000):
            engine.process(ev(i * 0.01, ip=f"192.0.2.{i % 200}"))
        engine.flush()
        assert engine.state_size()["rule_state"] > 0
        list(engine.run([ev(1_000, ip="198.51.100.1")]))
        assert engine.state_size()["rule_state"] <= 2
        assert engine.stats.groups_expired == 200

    def test_reorder_buffer_is_capped(self) -> None:
        engine = RuleEngine([count_rule()], lateness=timedelta(days=1), max_buffered=100)
        for i in range(1_000):
            engine.process(ev(i, n=i))
            assert engine.state_size()["buffered_events"] <= 100
        assert engine.stats.buffer_overflows > 0


def _alert_fingerprint(
    alerts: list[Alert],
) -> list[tuple[str, tuple[str, ...], datetime, datetime]]:
    return [(a.id, a.event_ids, a.first_seen, a.last_seen) for a in alerts]


@settings(max_examples=150, deadline=None)
@given(
    st.lists(
        st.tuples(
            st.integers(min_value=0, max_value=600),  # seconds offset
            st.sampled_from(["auth.signin.failure", "auth.signin.success"]),
            st.sampled_from(["192.0.2.1", "192.0.2.2"]),
            st.integers(min_value=0, max_value=30),  # arrival jitter within the lateness bound
        ),
        max_size=40,
    )
)
def test_any_arrival_order_within_lateness_gives_the_same_alerts(
    specs: list[tuple[int, str, str, int]],
) -> None:
    lateness = timedelta(seconds=30)
    events = [ev(t, action=a, ip=ip, n=i) for i, (t, a, ip, _) in enumerate(specs)]
    jitters = [j for *_, j in specs]
    arrival = [
        e
        for _, e in sorted(
            zip(jitters, events, strict=True),
            key=lambda p: p[1].timestamp + timedelta(seconds=p[0]),
        )
    ]
    rules = [count_rule(threshold=3), sequence_rule(first_count=2)]
    in_order, _ = run(rules, sorted(events, key=lambda e: (e.timestamp, e.id)))
    shuffled, engine = run(rules, arrival, lateness=lateness)
    assert engine.stats.late_events == 0
    assert _alert_fingerprint(shuffled) == _alert_fingerprint(in_order)


class TestMoreEdges:
    def test_ratio_window_slides(self) -> None:
        ratio = rule(
            {
                "request": {"event.action|startswith": "auth."},
                "failure": FAILURE,
                "aggregate": {
                    "group_by": ["source.ip"],
                    "window": "10s",
                    "ratio": {"selection": "failure", "gte": 1.0, "min_count": 3},
                },
                "condition": "request and aggregate",
            }
        )
        # The success at 0s leaves the window before the third failure arrives at 12s.
        events = [ev(0, action="auth.signin.success"), ev(5), ev(8), ev(12)]
        (alert,) = run([ratio], events)[0]
        assert "3 of 3" in alert.explanation

    def test_ratio_group_events_are_capped(self) -> None:
        ratio = rule(
            {
                "request": {"event.action|startswith": "auth."},
                "failure": FAILURE,
                "aggregate": {
                    "group_by": ["source.ip"],
                    "window": "1h",
                    "ratio": {"selection": "failure", "gte": 0.9, "min_count": 20},
                },
                "condition": "request and aggregate",
            }
        )
        events = [ev(i * 0.1, action="auth.signin.success", n=i) for i in range(10_050)]
        alerts, engine = run([ratio], events)
        assert alerts == []
        assert engine.stats.group_events_dropped == 50

    def test_distinct_keeps_only_recent_event_ids(self) -> None:
        distinct = rule(
            {
                "failure": FAILURE,
                "aggregate": {
                    "group_by": ["source.ip"],
                    "window": "1h",
                    "distinct": {"field": "user.name", "gte": 2},
                },
                "condition": "failure and aggregate",
            }
        )
        events = [ev(i, user__name="alice", n=i) for i in range(300)] + [ev(400, user__name="bob")]
        (alert,) = run([distinct], events)[0]
        assert len(alert.event_ids) <= MAX_ALERT_EVENT_IDS
        assert alert.first_seen == T0  # the real first event, not the oldest kept id

    def test_sequence_first_step_slides_within_one_entity(self) -> None:
        events = [ev(0), ev(300), ev(650), ev(660), ev(670, action="auth.signin.success")]
        (alert,) = run([sequence_rule()], events)[0]
        assert alert.first_seen == T0 + timedelta(seconds=300)

    def test_sequence_ungrouped_and_group_cap(self) -> None:
        engine = RuleEngine([sequence_rule()], max_groups=10)
        engine.process(ev(0, ip=None))
        for i in range(50):
            engine.process(ev(1 + i * 0.01, ip=f"192.0.2.{i}"))
        engine.flush()
        assert engine.stats.ungrouped_events == 1
        assert engine.stats.groups_evicted == 40

    def test_stats_as_dict(self) -> None:
        _, engine = run([count_rule()], [ev(0)])
        assert engine.stats.as_dict()["events_evaluated"] == 1


def test_future_timestamp_without_reference_time_disables_only_reordering() -> None:
    bogus = Event.model_validate(
        {
            "timestamp": datetime(2099, 1, 1, tzinfo=UTC),
            "log_source": "test",
            "event": {"action": "auth.signin.success", "category": "authentication"},
            "source": {"ip": "198.51.100.1"},
            "raw": "bogus",
        }
    )
    engine = RuleEngine([count_rule()], lateness=timedelta(seconds=30))
    alerts = [*engine.process(ev(0)), *engine.process(bogus)]
    for event in [ev(1), ev(2), ev(3)]:  # in order: still evaluated and still alert
        alerts += engine.process(event)
    alerts += engine.process(ev(2.5, n=9))  # out of order: now dropped as late
    alerts += engine.flush()
    assert len(alerts) == 1
    assert engine.stats.late_events == 1


class TestSequenceRestart:
    """A completed sequence must not hide a later, separate one."""

    def _signin_change(self) -> CompiledRule:
        return rule(
            {
                "signin": SUCCESS,
                "change": {"event.action": "account.password.changed"},
                "sequence": {
                    "by": ["source.ip"],
                    "within": "30m",
                    "steps": [{"selection": "signin"}, {"selection": "change"}],
                },
                "condition": "sequence",
            }
        )

    def test_second_signin_opens_a_new_window(self) -> None:
        events = [
            ev(0, action="auth.signin.success"),
            ev(120, action="account.password.changed"),
            ev(1200, action="auth.signin.success"),  # minute 20: a new sign-in
            ev(2700, action="account.password.changed"),  # minute 45: 25 min after it
        ]
        alerts = run([self._signin_change()], events)[0]
        assert len(alerts) == 2
        assert alerts[1].first_seen == T0 + timedelta(seconds=1200)

    def test_failures_after_success_start_a_new_sequence(self) -> None:
        first = [ev(i) for i in range(5)] + [ev(10, action="auth.signin.success")]
        second = [ev(600 + i, n=1) for i in range(5)]  # inside the old window
        late_success = [ev(1000, action="auth.signin.success", n=2)]  # after start + 15m
        alerts = run([sequence_rule(within="15m", first_count=5)], first + second + late_success)[0]
        assert len(alerts) == 2
        assert alerts[1].first_seen == T0 + timedelta(seconds=600)

    def test_success_before_a_new_first_step_completes_re_alerts(self) -> None:
        events = [ev(i) for i in range(3)] + [
            ev(10, action="auth.signin.success"),
            ev(20, n=1),  # one new failure: not enough for a fresh sequence
            ev(30, action="auth.signin.success", n=1),
        ]
        alerts = run([sequence_rule()], events)[0]
        assert len(alerts) == 2
        assert alerts[0].event_ids[:3] == alerts[1].event_ids[:3]
