# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Suppression files: loading, validation, matching, expiry and the suppressor's counters."""

from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

from prohori.ml.features import MAX_WINDOW_EVENT_IDS
from prohori.rules.engine import MAX_ALERT_EVENT_IDS
from prohori.schema import Alert
from prohori.suppress import (
    SuppressionFileError,
    Suppressions,
    Suppressor,
    load_suppressions,
)
from prohori.suppress.apply import COMPLETE_BELOW
from tests.unit.incidents.factories import T0, alert, at, event

ROOT = Path(__file__).resolve().parents[3]

ENTRY = """
suppressions:
  - id: office-grants
    rule: PRH-ADMIN-001
    match:
      user.id: u-0001
      source.ip|cidr: 192.0.2.0/24
    reason: planned onboarding
    owner: security-team
    expires: 2026-10-31
"""


def _load(tmp_path: Path, text: str) -> Suppressions:
    path = tmp_path / "suppressions.yml"
    path.write_text(text, encoding="utf-8")
    return load_suppressions(path)


def _errors(tmp_path: Path, text: str) -> list[str]:
    with pytest.raises(SuppressionFileError) as caught:
        _load(tmp_path, text)
    return [e.format("f") for e in caught.value.errors]


def _grant(when: datetime, user: str = "u-0001", ip: str = "192.0.2.10") -> Alert:
    grant = event(when, "admin.role.granted", ip=ip, user_id=user)
    return alert("PRH-ADMIN-001", [grant], entities={"user.id": user, "source.ip": ip})


def _suppressor(suppressions: Suppressions, *alerts_and_events: object) -> Suppressor:
    return Suppressor(suppressions)


# ---------------------------------------------------------------------- loading and validation


def test_the_example_file_is_valid() -> None:
    loaded = load_suppressions(ROOT / "samples" / "suppressions.yml")
    assert [e.id for e in loaded.entries] == ["planned-admin-onboarding"]
    assert loaded.entries[0].rules == ("PRH-ADMIN-001",)


def test_a_valid_entry_compiles(tmp_path: Path) -> None:
    loaded = _load(tmp_path, ENTRY)
    entry = loaded.entries[0]
    assert entry.id == "office-grants"
    assert entry.expires == date(2026, 10, 31)
    assert entry.covers("PRH-ADMIN-001")
    assert not entry.covers("PRH-ADMIN-002")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("[]", "must be a YAML mapping"),
        ("{}", "add at least one entry"),
        ("other: 1", "Extra inputs are not permitted"),
        (ENTRY.replace("    owner: security-team\n", ""), "owner: Field required"),
        (ENTRY.replace("    reason: planned onboarding\n", ""), "reason: Field required"),
        (ENTRY.replace("expires: 2026-10-31", "expires: soon"), "expires"),
        (ENTRY.replace("rule: PRH-ADMIN-001", "rule: admin"), "invalid rule id"),
        (ENTRY.replace("id: office-grants", "id: Office Grants"), "id: String should match"),
        (ENTRY.replace("user.id: u-0001", "user.nope: u-0001"), "unknown field 'user.nope'"),
        (ENTRY.replace("user.id: u-0001", "user.id|fuzzy: u-0001"), "unknown modifier"),
        (ENTRY.replace("192.0.2.0/24", "not-a-network"), "invalid CIDR network"),
        (ENTRY.replace("  - id", "  - timezone: Mars/Base\n    id"), "unknown timezone"),
        ("suppressions:\n  - &a {id: x}\n  - *a\n", "aliases are not allowed"),
    ],
)
def test_invalid_files_say_what_is_wrong(tmp_path: Path, text: str, expected: str) -> None:
    errors = _errors(tmp_path, text)
    assert any(expected in e for e in errors), errors


def test_errors_carry_line_numbers(tmp_path: Path) -> None:
    errors = _errors(tmp_path, ENTRY.replace("user.id: u-0001", "user.id|fuzzy: u-0001"))
    assert errors == [
        "f:6: suppressions[0].match.user.id|fuzzy: unknown modifier(s): fuzzy",
    ]


def test_a_star_entry_needs_matchers_and_stands_alone(tmp_path: Path) -> None:
    star = ENTRY.replace("rule: PRH-ADMIN-001", 'rule: "*"')
    assert any("needs field matchers" in e for e in _errors(tmp_path, _no_match(star)))
    both = ENTRY.replace("rule: PRH-ADMIN-001", 'rule: ["*", PRH-ADMIN-001]')
    assert any("covers every rule" in e for e in _errors(tmp_path, both))


def _no_match(text: str) -> str:
    return text.replace(
        "    match:\n      user.id: u-0001\n      source.ip|cidr: 192.0.2.0/24\n", "    match: {}\n"
    )


def test_duplicate_ids_are_refused(tmp_path: Path) -> None:
    allow = (
        "allow_ips:\n  - {id: office-grants, addresses: [192.0.2.1], reason: scanner, "
        "owner: it, expires: 2027-01-01}\n"
    )
    errors = _errors(tmp_path, ENTRY + allow)
    assert any("duplicate entry id 'office-grants'" in e for e in errors)


def test_allow_ips_need_valid_addresses(tmp_path: Path) -> None:
    text = (
        "allow_ips:\n  - {id: scanner, addresses: [192.0.2.300], reason: scanner, "
        "owner: it, expires: 2027-01-01}\n"
    )
    assert any("invalid IP address or network" in e for e in _errors(tmp_path, text))


def test_a_file_that_is_not_yaml_or_too_big(tmp_path: Path) -> None:
    assert any("invalid YAML" in e for e in _errors(tmp_path, "suppressions: [\n"))
    assert any("larger than" in e for e in _errors(tmp_path, "#" * 200_000))


def test_warnings_for_expired_entries_and_unknown_rules(tmp_path: Path) -> None:
    loaded = _load(tmp_path, ENTRY)
    assert loaded.warnings({"PRH-ADMIN-001"}, today=date(2026, 10, 31)) == []
    later = loaded.warnings({"PRH-ADMIN-001"}, today=date(2026, 11, 1))
    assert len(later) == 1
    assert "expired on 2026-10-31" in later[0]
    unknown = loaded.warnings({"PRH-AUTH-001"}, today=date(2026, 10, 1))
    assert unknown == [
        "suppression 'office-grants' names rule 'PRH-ADMIN-001', which is not loaded; it "
        "silences nothing for that rule"
    ]


# ---------------------------------------------------------------------- matching


def test_an_alert_whose_events_all_match_is_suppressed_and_counted(tmp_path: Path) -> None:
    suppressor = Suppressor(_load(tmp_path, ENTRY))
    grant = event(at(0), "admin.role.granted", ip="192.0.2.10", user_id="u-0001")
    suppressor.observe_one(grant)
    found = suppressor.apply(alert("PRH-ADMIN-001", [grant]))
    assert found.suppression is not None
    assert found.suppression.id == "office-grants"
    assert found.suppression.owner == "security-team"
    assert suppressor.total == 1
    assert suppressor.summary() == {
        "suppressed": 1,
        "suppressed_by_entry": {"office-grants": {"PRH-ADMIN-001": 1}},
    }
    assert suppressor.listed == [found]


def test_one_event_that_does_not_match_keeps_the_alert(tmp_path: Path) -> None:
    suppressor = Suppressor(_load(tmp_path, ENTRY))
    mine = event(at(0), "admin.role.granted", ip="192.0.2.10", user_id="u-0001")
    theirs = event(at(1), "admin.role.granted", ip="203.0.113.5", user_id="u-0001")
    for e in (mine, theirs):
        suppressor.observe_one(e)
    found = suppressor.apply(alert("PRH-ADMIN-001", [mine, theirs]))
    assert found.suppression is None
    assert suppressor.total == 0


def test_other_rules_and_other_accounts_are_untouched(tmp_path: Path) -> None:
    suppressor = Suppressor(_load(tmp_path, ENTRY))
    grant = event(at(0), "admin.role.granted", ip="192.0.2.10", user_id="u-0001")
    other = event(at(0), "admin.role.granted", ip="192.0.2.10", user_id="u-0002")
    for e in (grant, other):
        suppressor.observe_one(e)
    assert suppressor.apply(alert("PRH-ADMIN-002", [grant])).suppression is None
    assert suppressor.apply(alert("PRH-ADMIN-001", [other])).suppression is None


def test_expiry_is_decided_by_the_alert_time_not_the_clock(tmp_path: Path) -> None:
    suppressor = Suppressor(_load(tmp_path, ENTRY))  # expires 2026-10-31
    last_day = datetime(2026, 10, 31, 23, 59, 59, tzinfo=UTC)
    after = last_day + timedelta(seconds=1)
    for when in (last_day, after):
        suppressor.observe_one(event(when, "admin.role.granted", ip="192.0.2.1", user_id="u-0001"))
    in_force = alert(
        "PRH-ADMIN-001", [event(last_day, "admin.role.granted", ip="192.0.2.1", user_id="u-0001")]
    )
    expired = alert(
        "PRH-ADMIN-001", [event(after, "admin.role.granted", ip="192.0.2.1", user_id="u-0001")]
    )
    assert suppressor.apply(in_force).suppression is not None
    assert suppressor.apply(expired).suppression is None


def test_entities_decide_when_the_event_list_is_partial(tmp_path: Path) -> None:
    text = ENTRY.replace("rule: PRH-ADMIN-001", "rule: PRH-WEB-001").replace(
        "      user.id: u-0001\n", ""
    )
    suppressor = Suppressor(_load(tmp_path, text))
    events = [event(at(0, n), "web.request", ip="192.0.2.10") for n in range(COMPLETE_BELOW)]
    for e in events:
        suppressor.observe_one(e)
    # A list at the cap may be missing events, so the events alone never decide; the alert's
    # entities (shared by every event of a threshold alert) do.
    partial = alert("PRH-WEB-001", events, entities={"source.ip": "192.0.2.10"})
    assert suppressor.apply(partial).suppression is not None
    without_entities = alert("PRH-WEB-001", events)
    assert suppressor.apply(without_entities).suppression is None


def test_entities_only_decide_when_every_field_is_an_entity(tmp_path: Path) -> None:
    suppressor = Suppressor(_load(tmp_path, ENTRY))  # user.id and source.ip
    unseen = _grant(at(0))  # its event was never observed
    only_user = alert("PRH-ADMIN-001", [], entities={"user.id": "u-0001"})
    assert suppressor.apply(unseen).suppression is not None  # both fields are entities
    assert suppressor.apply(only_user).suppression is None


def test_forgotten_events_fall_back_to_entities(tmp_path: Path) -> None:
    suppressor = Suppressor(_load(tmp_path, ENTRY), max_tracked=1)
    first = event(at(0), "admin.role.granted", ip="192.0.2.10", user_id="u-0001")
    second = event(at(1), "admin.role.granted", ip="192.0.2.11", user_id="u-0001")
    suppressor.observe_one(first)
    suppressor.observe_one(second)
    assert suppressor.forgotten == 1
    # The first event is forgotten and the alert has no entities: not suppressed (fail open).
    assert suppressor.apply(alert("PRH-ADMIN-001", [first])).suppression is None
    assert suppressor.apply(alert("PRH-ADMIN-001", [second])).suppression is not None


def test_time_fields_use_the_entry_timezone(tmp_path: Path) -> None:
    text = ENTRY.replace(
        "      source.ip|cidr: 192.0.2.0/24\n", "      time.hour|lt: 18\n"
    ).replace("  - id", "  - timezone: Asia/Dhaka\n    id")
    suppressor = Suppressor(_load(tmp_path, text))
    # 11:30 UTC is 17:30 in Dhaka (in hours); 12:30 UTC is 18:30 (out of hours).
    day = T0.replace(hour=0, minute=0)
    inside = event(day.replace(hour=11, minute=30), "admin.role.granted", user_id="u-0001")
    outside = event(day.replace(hour=12, minute=30), "admin.role.granted", user_id="u-0001")
    for e in (inside, outside):
        suppressor.observe_one(e)
    assert suppressor.apply(alert("PRH-ADMIN-001", [inside])).suppression is not None
    assert suppressor.apply(alert("PRH-ADMIN-001", [outside])).suppression is None


def test_the_first_matching_entry_wins_and_listing_is_bounded(tmp_path: Path) -> None:
    text = ENTRY + (
        "  - id: everything-from-the-office\n"
        '    rule: "*"\n'
        "    match: {source.ip|cidr: 192.0.2.0/24}\n"
        "    reason: office network\n"
        "    owner: it\n"
        "    expires: 2027-01-01\n"
    )
    suppressor = Suppressor(_load(tmp_path, text), max_listed=2)
    alerts = [_grant(at(n)) for n in range(3)]
    marked = [suppressor.apply(a) for a in alerts]
    assert {m.suppression.id for m in marked if m.suppression} == {"office-grants"}
    assert suppressor.total == 3
    assert len(suppressor.listed) == 2
    other = suppressor.apply(alert("PRH-WEB-001", [], entities={"source.ip": "192.0.2.4"}))
    assert other.suppression is not None
    assert other.suppression.id == "everything-from-the-office"


def test_no_file_means_no_change() -> None:
    suppressor = Suppressor()
    unchanged = _grant(at(0))
    assert suppressor.apply(unchanged) is unchanged
    assert not suppressor


def test_the_event_lists_of_rules_and_models_share_one_cap() -> None:
    assert MAX_ALERT_EVENT_IDS == MAX_WINDOW_EVENT_IDS == COMPLETE_BELOW


# ---------------------------------------------------------------------- the alert schema


def test_alerts_without_a_suppression_serialise_as_before(tmp_path: Path) -> None:
    plain = _grant(at(0))
    assert "suppression" not in plain.model_dump_json()
    assert "suppression" not in plain.model_dump()
    suppressor = Suppressor(_load(tmp_path, ENTRY))
    marked = suppressor.apply(plain)
    text = marked.model_dump_json()
    assert '"suppression":{"id":"office-grants"' in text
    assert Alert.model_validate_json(text) == marked
    assert marked.id == plain.id  # the id never depends on the suppression


# ---------------------------------------------------------------------- allow-listed addresses


def test_allow_ips_suppress_and_list_addresses(tmp_path: Path) -> None:
    text = (
        "allow_ips:\n"
        "  - id: vuln-scanner\n"
        "    addresses: [192.0.2.50, 2001:db8:1::/48]\n"
        "    reason: weekly authorised scan\n"
        "    owner: it\n"
        "    expires: 2026-12-31\n"
    )
    loaded = _load(tmp_path, text)
    assert loaded.allowed_ip("192.0.2.50", T0) is not None
    assert loaded.allowed_ip("2001:db8:1::9", T0) is not None
    assert loaded.allowed_ip("192.0.2.51", T0) is None
    assert loaded.allowed_ip("not-an-ip", T0) is None
    assert loaded.allowed_ip("192.0.2.50", datetime(2027, 1, 1, tzinfo=UTC)) is None
    suppressor = Suppressor(loaded)
    scan = event(at(0), "web.request", ip="192.0.2.50")
    suppressor.observe_one(scan)
    assert suppressor.apply(alert("PRH-WEB-001", [scan])).suppression is not None
