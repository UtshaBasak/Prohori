"""Grouping alerts into incidents: shared entities, time gaps and shared addresses."""

from datetime import timedelta

import pytest
from tests.unit.incidents.factories import alert, at, event

from prohori.incidents import AlertGroup, EventContext, group_alerts, link_keys
from prohori.schema import Alert


def _ids(groups: list[AlertGroup]) -> list[list[str]]:
    return [[a.detector_id for a in g.alerts] for g in groups]


@pytest.mark.parametrize(
    "field",
    ["source.ip", "user.id", "user.name", "user.email_hash", "request_id", "extra.session_id"],
)
def test_alerts_sharing_an_entity_are_grouped(field: str) -> None:
    a = alert("R-A", start=at(0), entities={field: "x-1"})
    b = alert("R-B", start=at(5), entities={field: "x-1"})
    c = alert("R-C", start=at(6), entities={field: "x-2"})
    assert _ids(group_alerts([a, b, c])) == [["R-A", "R-B"], ["R-C"]]


def test_same_value_in_different_fields_does_not_link() -> None:
    a = alert("R-A", entities={"user.id": "203.0.113.7"})
    b = alert("R-B", entities={"source.ip": "203.0.113.7"})
    assert len(group_alerts([a, b])) == 2


@pytest.mark.parametrize("field", ["host", "log_source"])
def test_host_and_log_source_never_link(field: str) -> None:
    a = alert("R-A", start=at(0), entities={field: "web01"})
    b = alert("R-B", start=at(1), entities={field: "web01"})
    assert len(group_alerts([a, b])) == 2


def test_gap_boundary_is_inclusive() -> None:
    gap = timedelta(minutes=30)
    a = alert("R-A", start=at(0), end=at(10), entities={"source.ip": "203.0.113.7"})
    exactly = alert("R-B", start=at(40), entities={"source.ip": "203.0.113.7"})
    assert len(group_alerts([a, exactly], gap=gap)) == 1
    late = alert("R-B", start=at(40, seconds=1), entities={"source.ip": "203.0.113.7"})
    assert len(group_alerts([a, late], gap=gap)) == 2


def test_gap_counts_from_the_latest_end_of_the_chain() -> None:
    long = alert("R-A", start=at(0), end=at(60), entities={"source.ip": "203.0.113.7"})
    short = alert("R-B", start=at(1), end=at(2), entities={"source.ip": "203.0.113.7"})
    later = alert("R-C", start=at(80), entities={"source.ip": "203.0.113.7"})
    assert _ids(group_alerts([long, short, later])) == [["R-A", "R-B", "R-C"]]


def test_links_are_transitive() -> None:
    by_ip = alert("R-A", start=at(0), entities={"source.ip": "203.0.113.7"})
    both = alert("R-B", start=at(1), entities={"source.ip": "203.0.113.7", "user.id": "u-1"})
    by_user = alert("R-C", start=at(2), entities={"user.id": "u-1"})
    assert _ids(group_alerts([by_user, both, by_ip])) == [["R-A", "R-B", "R-C"]]


def test_result_does_not_depend_on_input_order() -> None:
    alerts = [
        alert(f"R-{n}", start=at(n * 7), entities={"source.ip": f"203.0.113.{n % 3}"})
        for n in range(12)
    ]
    expected = [[a.id for a in g.alerts] for g in group_alerts(alerts)]
    for shift in range(1, 6):
        shuffled = list(reversed(alerts[shift:])) + alerts[:shift]
        assert [[a.id for a in g.alerts] for g in group_alerts(shuffled)] == expected


def test_duplicate_alerts_are_counted_once() -> None:
    a = alert("R-A", entities={"source.ip": "203.0.113.7"})
    assert len(group_alerts([a, a])[0].alerts) == 1


def test_takeover_chain_links_through_event_entities() -> None:
    context = EventContext()
    failures = [event(at(0, seconds=s), user_id="u-1") for s in range(10)]
    signin = event(at(1), "auth.signin.success", user_id="u-1")
    change = event(at(2), "account.bkash.changed", user_id="u-1", ip="198.51.100.9")
    for e in [*failures, signin, change]:
        context.add(e)
    brute = alert("PRH-AUTH-001", failures, entities={"source.ip": "203.0.113.7"})
    # The account change happened from another IP: only the user id ties it to the brute force.
    takeover = alert("PRH-ACCT-001", [signin, change], entities={"user.id": "u-1"})
    assert len(group_alerts([brute, takeover])) == 2  # alert entities alone do not link them
    groups = group_alerts([brute, takeover], context)
    assert _ids(groups) == [["PRH-AUTH-001", "PRH-ACCT-001"]]
    assert ("user.id", "u-1") in groups[0].keys


def test_only_single_valued_event_fields_become_links() -> None:
    context = EventContext()
    events = [event(at(0, seconds=s), "ssh.login.failure", user_name=f"user{s}") for s in range(5)]
    for e in events:
        context.add(e)
    keys = link_keys(alert("PRH-AUTH-001", events, entities={"source.ip": "203.0.113.7"}), context)
    assert keys == {("source.ip", "203.0.113.7")}


def test_shared_ip_stops_linking_after_the_fanout_limit() -> None:
    alerts = [
        alert(f"R-{n}", start=at(n), entities={"source.ip": "192.0.2.1", "user.id": f"u-{n}"})
        for n in range(6)
    ]
    groups = group_alerts(alerts, max_ip_fanout=3)
    assert [len(g.alerts) for g in groups] == [3, 1, 1, 1]
    assert groups[0].shared_ips == (("192.0.2.1", 4),)
    assert all(g.shared_ips == (("192.0.2.1", 4),) for g in groups)


def test_fanout_counts_accounts_not_alerts() -> None:
    alerts = [
        alert(f"R-{n}", start=at(n), entities={"source.ip": "192.0.2.1", "user.id": "u-1"})
        for n in range(20)
    ]
    groups = group_alerts(alerts, max_ip_fanout=2)
    assert len(groups) == 1
    assert groups[0].shared_ips == ()


def test_invalid_settings() -> None:
    with pytest.raises(ValueError, match="gap"):
        group_alerts([], gap=timedelta(seconds=-1))
    with pytest.raises(ValueError, match="fanout"):
        group_alerts([], max_ip_fanout=0)


def test_no_alerts() -> None:
    assert group_alerts([]) == []


def test_alert_without_links_is_its_own_incident() -> None:
    lonely: Alert = alert("R-A")
    assert _ids(group_alerts([lonely, alert("R-B")])) == [["R-A"], ["R-B"]]
