# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""The bound on alerts held by the batch commands."""

import pytest
from tests.unit.incidents.factories import alert, at

from prohori.incidents import build_incidents
from prohori.incidents.cap import AlertCap, alert_key


def test_few_keys_keep_the_first_alerts_of_each() -> None:
    cap = AlertCap(per_key=3, total=100)
    alerts = [alert("R-A", start=at(n), entities={"source.ip": "203.0.113.7"}) for n in range(10)]
    alerts += [alert("R-B", start=at(n), entities={"source.ip": "203.0.113.7"}) for n in range(2)]
    cap.extend(alerts)
    assert cap.alerts == alerts[:3] + alerts[10:]
    assert (cap.seen, cap.dropped_total) == (12, 7)
    assert cap.dropped == {alert_key(alerts[0]): 7}


def test_many_keys_stop_at_the_overall_bound() -> None:
    cap = AlertCap(per_key=5, total=50)
    for n in range(1_000):
        cap.add(alert("R-A", start=at(n), entities={"source.ip": f"10.0.{n // 250}.{n % 250}"}))
    assert len(cap.alerts) == 50
    assert cap.seen == 1_000
    assert cap.dropped_total == 950


def test_dropped_counters_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("prohori.incidents.cap.MAX_COUNTED_KEYS", 10)
    cap = AlertCap(per_key=1, total=1)
    for n in range(100):
        cap.add(alert("R-A", start=at(n), entities={"user.id": f"u-{n}"}))
    assert len(cap.dropped) == 10
    assert cap.dropped_total == 99


def test_incidents_that_lost_alerts_say_so() -> None:
    cap = AlertCap(per_key=2, total=100)
    cap.extend(alert("R-A", start=at(n), entities={"source.ip": "203.0.113.7"}) for n in range(5))
    cap.add(alert("R-B", start=at(300), entities={"source.ip": "198.51.100.9"}))
    incidents = cap.apply(build_incidents(cap.alerts))
    by_ip = {i.entities["source.ip"][0]: i for i in incidents}
    (note,) = [x for x in by_ip["203.0.113.7"].limitations if "not kept" in x]
    assert note.startswith("3 more R-A alert(s) for source.ip=203.0.113.7")
    assert not [x for x in by_ip["198.51.100.9"].limitations if "not kept" in x]
    assert by_ip["203.0.113.7"].id == build_incidents(cap.alerts)[0].id  # ids are unchanged


def test_limits_must_be_positive() -> None:
    with pytest.raises(ValueError, match="at least 1"):
        AlertCap(per_key=0)
