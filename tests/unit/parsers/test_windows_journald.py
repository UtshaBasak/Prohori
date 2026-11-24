# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Tests for the Windows Security event parser, its mapping, ``.evtx`` reading and journald."""

import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from prohori.parsers import (
    AuthLogParser,
    JournaldParser,
    ParseStats,
    WindowsSecurityParser,
    detect_format,
    evtx_file,
    iter_text_lines,
    read_lines,
)
from prohori.parsers.windows import TEMPLATES, WindowsRecord, positional, to_event
from prohori.rules import builtin_rules_dir, load_rules
from prohori.rules.engine import RuleEngine
from prohori.schema import Event

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples" / "logs"
SEC = "Microsoft-Windows-Security-Auditing"
T = datetime(2026, 10, 24, 14, 0, tzinfo=UTC)
NS = "http://schemas.microsoft.com/win/2004/08/events/event"

FAILURE = {
    "SubjectUserSid": "S-1-0-0",
    "TargetUserSid": "S-1-0-0",
    "TargetUserName": "administrator",
    "TargetDomainName": "CORP",
    "Status": "0xc000006d",
    "SubStatus": "0xc000006a",
    "LogonType": "10",
    "WorkstationName": "KALI",
    "IpAddress": "203.0.113.50",
    "IpPort": "49152",
}


def beat(event_id: int = 4625, data: dict[str, str] | None = None, **winlog: Any) -> str:
    record = {
        "@timestamp": "2026-10-24T14:00:00.000Z",
        "winlog": {
            "channel": "Security",
            "computer_name": "DC01.corp.example",
            "event_id": str(event_id),
            "provider_name": SEC,
            "record_id": "7",
            "event_data": FAILURE if data is None else data,
            **winlog,
        },
    }
    return json.dumps(record)


def xml(event_id: int = 4625, data: dict[str, str] | None = None, provider: str = SEC) -> str:
    values = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in (data or FAILURE).items())
    return (
        f'<Event xmlns="{NS}"><System><Provider Name="{provider}"/><EventID>{event_id}</EventID>'
        '<TimeCreated SystemTime="2026-10-24T14:00:00.1234567Z"/><EventRecordID>9</EventRecordID>'
        "<Channel>Security</Channel><Computer>DC01.corp.example</Computer></System>"
        f"<EventData>{values}</EventData></Event>"
    )


def parse(*lines: str, **options: Any) -> tuple[list[Event], ParseStats]:
    stats = ParseStats()
    parser = WindowsSecurityParser(**options)
    events = list(parser.parse(iter_text_lines(lines), source="security.json", stats=stats))
    return events, stats


def balanced(stats: ParseStats) -> bool:
    return stats.lines == stats.events + stats.skipped + stats.blank + stats.errors


class TestMapping:
    def test_failed_sign_in(self) -> None:
        (event,), _ = parse(beat())
        assert (event.event.action, event.event.category, event.event.outcome) == (
            "windows.logon.failure",
            "authentication",
            "failure",
        )
        assert event.event.reason == "bad_password"
        assert event.user.name == "administrator"
        assert event.user.id is None  # the null SID is not an account
        assert str(event.source.ip) == "203.0.113.50"
        assert event.host == "dc01.corp.example"
        assert event.log_source == "windows-security"
        assert event.extra["logon_type"] == 10
        assert event.extra["logon_type_name"] == "remote_interactive"
        assert event.extra["workstation"] == "KALI"
        assert event.extra["source_port"] == 49152
        assert event.extra["event_id"] == 4625

    @pytest.mark.parametrize(
        ("status", "sub", "reason"),
        [
            ("0xc000006d", "0xc0000064", "unknown_user"),
            ("0xC000006D", "0xC000006A", "bad_password"),
            ("0xc0000234", "0x0", "locked"),
            ("0xc000006e", "0xc0000072", "disabled"),
            ("0xc000006d", "0xc0000999", "auth_failed"),
            ("0xc000015b", "0x0", "logon_type_not_granted"),
        ],
    )
    def test_failure_reasons(self, status: str, sub: str, reason: str) -> None:
        (event,), _ = parse(beat(data={**FAILURE, "Status": status, "SubStatus": sub}))
        assert event.event.reason == reason

    def test_successful_sign_in(self) -> None:
        data = {
            "TargetUserSid": "S-1-5-21-1-2-3-500",
            "TargetUserName": "administrator",
            "LogonType": "3",
            "IpAddress": "::ffff:192.0.2.41",
            "WorkstationName": "WS01",
        }
        (event,), _ = parse(beat(4624, data))
        assert event.event.action == "windows.logon.success"
        assert event.user.id == "S-1-5-21-1-2-3-500"
        assert str(event.source.ip) == "192.0.2.41"
        assert event.extra["logon_type_name"] == "network"

    def test_no_address(self) -> None:
        (event,), _ = parse(beat(data={**FAILURE, "IpAddress": "-", "IpPort": "-"}))
        assert event.source.ip is None
        assert "source_port" not in event.extra

    def test_host_name_in_the_address_field(self) -> None:
        (event,), _ = parse(beat(data={**FAILURE, "IpAddress": "Attacker.Example"}))
        assert event.source.host == "attacker.example"
        assert event.extra["source_host"] == "Attacker.Example"

    @pytest.mark.parametrize(
        ("event_id", "action", "category"),
        [
            (4634, "windows.logoff", "session"),
            (4647, "windows.logoff", "session"),
            (4672, "windows.logon.special_privileges", "authorization"),
            (4720, "windows.account.created", "account"),
            (4722, "windows.account.enabled", "account"),
            (4726, "windows.account.deleted", "account"),
            (4728, "windows.group.member_added", "account"),
            (4732, "windows.group.member_added", "account"),
            (4756, "windows.group.member_added", "account"),
            (4740, "windows.account.locked_out", "authentication"),
        ],
    )
    def test_every_event_id(self, event_id: int, action: str, category: str) -> None:
        data = {
            "TargetUserName": "amina",
            "TargetSid": "S-1-5-21-1-2-3-1106",
            "SubjectUserName": "it-admin",
            "SubjectUserSid": "S-1-5-21-1-2-3-500",
            "MemberSid": "S-1-5-21-1-2-3-1190",
        }
        (event,), _ = parse(beat(event_id, data))
        assert (event.event.action, event.event.category) == (action, category)

    def test_group_addition(self) -> None:
        data = {
            "MemberName": "CN=svc,CN=Users,DC=corp,DC=example",
            "MemberSid": "S-1-5-21-1-2-3-1190",
            "TargetUserName": "Administrators",
            "TargetDomainName": "Builtin",
            "TargetSid": "S-1-5-32-544",
            "SubjectUserName": "it-admin",
            "SubjectUserSid": "S-1-5-21-1-2-3-500",
        }
        (event,), _ = parse(beat(4732, data))
        assert event.user.name == "it-admin"  # who made the change
        assert event.extra["group_sid"] == "S-1-5-32-544"
        assert event.extra["group_scope"] == "local"
        assert event.extra["member_sid"] == "S-1-5-21-1-2-3-1190"

    def test_lockout_names_the_caller_computer(self) -> None:
        data = {"TargetUserName": "amina", "TargetDomainName": "KALI", "TargetSid": "S-1-5-21-9"}
        (event,), _ = parse(beat(4740, data))
        assert event.event.reason == "locked"
        assert event.extra["caller_computer"] == "KALI"
        assert "target_domain" not in event.extra

    def test_special_privileges_list_is_one_line(self) -> None:
        data = {
            "SubjectUserName": "it-admin",
            "PrivilegeList": "SeBackupPrivilege\n\t\tSeDebugPrivilege",
        }
        (event,), _ = parse(beat(4672, data))
        assert event.extra["privileges"] == "SeBackupPrivilege SeDebugPrivilege"

    def test_log_cleared(self) -> None:
        line = beat(
            1102,
            {},
            provider_name="Microsoft-Windows-Eventlog",
            user_data={"SubjectUserName": "administrator", "xml_name": "LogFileCleared"},
        )
        (event,), _ = parse(line)
        assert event.event.action == "windows.log.cleared"
        assert event.user.name == "administrator"

    def test_unmapped_ids_and_other_providers_are_skipped(self) -> None:
        events, stats = parse(beat(4688), beat(4625, provider_name="Some-Other-Provider"))
        assert (events, stats.skipped) == ([], 2)

    def test_mapping_is_independent_of_the_format(self) -> None:
        record = WindowsRecord(SEC, 4625, T, "DC01.corp.example", 7, "Security", FAILURE)
        event = to_event(record, raw="x", position="p")
        assert event is not None
        assert event.user.name == "administrator"

    def test_templates_cover_every_mapped_id(self) -> None:
        assert set(TEMPLATES) == {
            4624,
            4625,
            4634,
            4647,
            4672,
            4720,
            4722,
            4726,
            4728,
            4732,
            4756,
            4740,
            1102,
        }
        assert (
            positional(4625, ["S-1-0-0", "-", "-", "0x0", "S-1-0-0", "bob"])["TargetUserName"]
            == "bob"
        )


class TestFormats:
    def test_xml_one_line(self) -> None:
        (event,), _ = parse(xml())
        assert event.timestamp == datetime(2026, 10, 24, 14, 0, 0, 123456, tzinfo=UTC)
        assert event.extra["record_id"] == 9
        assert event.user.name == "administrator"

    def test_xml_over_several_lines(self) -> None:
        text = xml().replace("<System>", "\n  <System>").replace("<EventData>", "\n  <EventData>")
        lines = [
            '<?xml version="1.0" encoding="UTF-8"?>',
            "<Events>",
            *text.split("\n"),
            "</Events>",
        ]
        events, stats = parse(*lines)
        assert len(events) == 1
        assert (stats.errors, stats.skipped) == (0, len(lines) - 1)
        assert balanced(stats)

    def test_xml_user_data(self) -> None:
        line = (
            f'<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Eventlog"/>'
            '<EventID>1102</EventID><TimeCreated SystemTime="2026-10-24T14:00:00Z"/></System>'
            '<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">'
            "<SubjectUserName>administrator</SubjectUserName></LogFileCleared></UserData></Event>"
        )
        (event,), _ = parse(line)
        assert event.event.action == "windows.log.cleared"
        assert event.user.name == "administrator"

    @pytest.mark.parametrize(
        ("line", "reason"),
        [
            ('<!DOCTYPE x [<!ENTITY a "aaaa">]><Event></Event>', "not an <Event>"),
            (f'<Event xmlns="{NS}"><!DOCTYPE x></Event>', "DOCTYPE"),
            (f'<Event xmlns="{NS}"><!ENTITY a "b"></Event>', "entity"),
            ("<Event><System></Event>", "invalid XML"),
            ("<Event></Event><Event></Event>", "more than one event"),
            ("<Other/>", "not an <Event>"),
            ("<Event><EventData/></Event>", "without <System>"),
        ],
    )
    def test_hostile_xml(self, line: str, reason: str) -> None:
        events, stats = parse(line)
        assert (events, stats.errors) == ([], 1)
        assert reason in stats.error_examples[0].reason

    def test_unterminated_xml_is_bounded(self) -> None:
        lines = ["<Event>", *(["<Data>" + "x" * 1000 + "</Data>"] * 70), xml()]
        events, stats = parse(*lines)
        assert "longer than" in stats.error_examples[0].reason
        assert len(events) == 1  # the next event is read again
        assert balanced(stats)

    def test_nxlog_local_time(self) -> None:
        record = {
            "EventTime": "2026-10-24 20:00:00",
            "Hostname": "DC01.corp.example",
            "EventID": 4625,
            "SourceName": SEC,
            **FAILURE,
        }
        (event,), _ = parse(json.dumps(record), timezone="Asia/Dhaka")
        assert event.timestamp == T
        assert event.user.name == "administrator"

    @pytest.mark.parametrize(
        "created", ["/Date(1792850400000)/", "2026-10-24T20:00:00.0000000+06:00"]
    )
    def test_get_winevent_json(self, created: str) -> None:
        values = [FAILURE.get(name, "-") for name in TEMPLATES[4625]]
        record = {
            "Id": 4625,
            "ProviderName": SEC,
            "MachineName": "DC01.corp.example",
            "TimeCreated": created,
            "RecordId": 12,
            "LogName": "Security",
            "Properties": [{"Value": v} for v in values],
            "Message": "An account failed to log on.",
        }
        (event,), _ = parse(json.dumps(record))
        assert event.timestamp == T
        assert (event.user.name, event.event.reason) == ("administrator", "bad_password")
        assert str(event.source.ip) == "203.0.113.50"

    def test_evtx_dump_json(self) -> None:
        record = {
            "Event": {
                "#attributes": {"xmlns": NS},
                "System": {
                    "Provider": {"#attributes": {"Name": SEC}},
                    "EventID": {"#text": 4625, "#attributes": {"Qualifiers": ""}},
                    "TimeCreated": {"#attributes": {"SystemTime": "2026-10-24T14:00:00.000000Z"}},
                    "EventRecordID": 5,
                    "Channel": "Security",
                    "Computer": "DC01.corp.example",
                },
                "EventData": FAILURE,
            }
        }
        (event,), _ = parse(json.dumps(record))
        assert event.timestamp == T
        assert event.extra["record_id"] == 5

    @pytest.mark.parametrize(
        ("record", "reason"),
        [
            ({"foo": 1}, "not a Windows event record"),
            ({"EventID": "x", "SourceName": SEC}, "event id"),
            ({"EventID": 4625, "SourceName": SEC, "EventTime": 5}, "time"),
            ({"EventID": 4625, "SourceName": SEC, "EventTime": "never"}, "time"),
            ({"Id": 4625, "TimeCreated": "/Date(99999999999999999)/"}, "time"),
            ({"evtx_error": "unreadable record: RuntimeError"}, "evtx: unreadable"),
            (
                {
                    "EventID": 4625,
                    "SourceName": SEC,
                    "EventTime": "2026-10-24T14:00:00Z",
                    "LogonType": "ten",
                },
                "LogonType",
            ),
        ],
    )
    def test_malformed_json(self, record: dict[str, Any], reason: str) -> None:
        events, stats = parse(json.dumps(record))
        assert (events, stats.errors) == ([], 1)
        assert reason in stats.error_examples[0].reason

    def test_sample_files(self) -> None:
        for name, count in (("windows-security.jsonl", 33), ("windows-security.xml", 20)):
            stats = ParseStats()
            events = list(WindowsSecurityParser().parse_file(SAMPLES / name, stats=stats))
            assert (stats.errors, len(events)) == (0, count), name
            assert balanced(stats)

    def test_samples_are_detected(self) -> None:
        for name, expected in (
            ("windows-security.jsonl", "windows_security"),
            ("windows-security.xml", "windows_security"),
            ("journald.json", "journald"),
        ):
            with (SAMPLES / name).open("rb") as stream:
                assert detect_format(read_lines(stream)) == expected, name

    @settings(max_examples=300)
    @given(st.text(max_size=300))
    def test_arbitrary_text_never_raises(self, text: str) -> None:
        _, stats = parse(*text.split("\n"))
        assert balanced(stats)

    @settings(max_examples=300)
    @given(
        st.lists(
            st.sampled_from(["<Event>", "</Event>", "<System>", "<Events>", xml(), "{}", "x"]),
            max_size=12,
        )
    )
    def test_arbitrary_xml_fragments_never_raise(self, lines: list[str]) -> None:
        _, stats = parse(*lines)
        assert balanced(stats)


class _FakeParser:
    def __init__(self, records: list[object]) -> None:
        self.records = records

    def records_json(self) -> Any:
        for record in self.records:
            if isinstance(record, Exception):
                raise record
            yield record


class TestEvtx:
    def test_records_become_lines_and_bad_records_errors(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        good = {"Event": {"System": {"EventID": 4688}}}
        records = iter(
            [
                {"event_record_id": 1, "data": json.dumps(good, indent=2)},
                {"event_record_id": 2, "data": "not json"},
            ]
        )

        def fake_records() -> Any:
            yield from records
            raise RuntimeError("bad chunk")

        class Fake:
            def __init__(self, path: str) -> None:
                self.path = path

            def records_json(self) -> Any:
                return fake_records()

        import sys
        import types

        module = types.ModuleType("evtx")
        module.PyEvtxParser = Fake  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "evtx", module)
        path = tmp_path / "Security.evtx"
        path.write_bytes(b"ElfFile\x00" + b"\x00" * 100)
        stream = evtx_file.EvtxLines(path)
        lines = list(read_lines(stream))
        assert json.loads(lines[0].text) == good
        assert "record without JSON data" in lines[1].text
        assert "unreadable record: RuntimeError" in lines[2].text
        assert stream.bytes == 108
        assert len(stream.hexdigest()) == 64

    def test_readline_respects_the_size_limit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import sys
        import types

        long = {"Event": {"System": {"EventID": 1}, "x": "y" * 100}}

        class Fake:
            def __init__(self, path: str) -> None:
                pass

            def records_json(self) -> Any:
                yield {"data": json.dumps(long)}

        module = types.ModuleType("evtx")
        module.PyEvtxParser = Fake  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "evtx", module)
        path = tmp_path / "a.evtx"
        path.write_bytes(b"x")
        stream = evtx_file.EvtxLines(path)
        first = stream.readline(50)
        assert len(first) == 50
        assert (first + stream.readline()).endswith(b"\n")
        assert stream.readline() == b""

    def test_available_reflects_the_import(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import sys

        monkeypatch.setitem(sys.modules, "evtx", None)
        assert not evtx_file.evtx_available()


def _journal(message: object, **fields: Any) -> str:
    record = {
        "__REALTIME_TIMESTAMP": "1792850400123456",
        "_HOSTNAME": "web01",
        "SYSLOG_IDENTIFIER": "sshd",
        "SYSLOG_PID": "2120",
        "MESSAGE": message,
        **fields,
    }
    return json.dumps(record)


def parse_journal(*lines: str) -> tuple[list[Event], ParseStats]:
    stats = ParseStats()
    events = list(JournaldParser().parse(iter_text_lines(lines), source="j.json", stats=stats))
    return events, stats


class TestJournald:
    def test_sshd_failure(self) -> None:
        (event,), _ = parse_journal(
            _journal("Failed password for root from 203.0.113.7 port 51234 ssh2")
        )
        assert event.event.action == "ssh.login.failure"
        assert event.log_source == "sshd"
        assert event.host == "web01"
        assert event.timestamp == T + timedelta(microseconds=123456)
        assert event.extra["pid"] == 2120

    def test_byte_array_message_and_comm_fallback(self) -> None:
        message = list(b"Accepted publickey for alice from 192.0.2.10 port 22 ssh2: \xff")
        (event,), _ = parse_journal(
            _journal(message, SYSLOG_IDENTIFIER=None, SYSLOG_PID=None, _COMM="sshd", _PID="9")
        )
        assert event.event.action == "ssh.login.success"
        assert event.extra["pid"] == 9

    def test_sudo_and_pam(self) -> None:
        sudo = _journal(
            "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
            SYSLOG_IDENTIFIER="sudo",
        )
        pam = _journal(
            "pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= "
            "rhost=203.0.113.7  user=root"
        )
        (first, second), _ = parse_journal(sudo, pam)
        assert first.event.action == "sudo.command"
        assert second.event.action == "pam.auth.failure"

    def test_other_programs_are_skipped(self) -> None:
        events, stats = parse_journal(
            _journal("Started Session 4.", SYSLOG_IDENTIFIER="systemd"),
            _journal("x", SYSLOG_IDENTIFIER=None),
        )
        assert (events, stats.skipped) == ([], 2)

    @pytest.mark.parametrize(
        ("line", "reason"),
        [
            (_journal("x", __REALTIME_TIMESTAMP="soon"), "__REALTIME_TIMESTAMP"),
            (_journal("x", __REALTIME_TIMESTAMP="123456789012345678"), "__REALTIME_TIMESTAMP"),
            (_journal({"a": 1}), "MESSAGE"),
            (_journal([1, 2, 300]), "byte values"),
            (_journal("x", SYSLOG_PID="12a"), "process id"),
            ("[]", "not an object"),
        ],
    )
    def test_malformed_entries(self, line: str, reason: str) -> None:
        events, stats = parse_journal(line)
        assert (events, stats.errors) == ([], 1)
        assert reason in stats.error_examples[0].reason

    @settings(max_examples=300)
    @given(st.text(max_size=300))
    def test_arbitrary_text_never_raises(self, text: str) -> None:
        _, stats = parse_journal(*text.split("\n"))
        assert balanced(stats)


def _alerts(events: list[Event]) -> list[tuple[object, ...]]:
    rules = [r.rule for r in load_rules([builtin_rules_dir()]) if r.rule is not None]
    engine = RuleEngine(rules)
    alerts = [a for e in events for a in engine.process(e)] + engine.flush()
    return sorted(
        (
            a.detector_id,
            tuple(sorted(a.entities.items())),
            a.first_seen.replace(microsecond=0),
            a.last_seen.replace(microsecond=0),
            len(a.event_ids),
        )
        for a in alerts
    )


def test_the_same_sshd_lines_give_the_same_alerts_through_journald() -> None:
    """Definition of done of step 34: auth.log and the journal give the same alerts."""
    syslog = list(AuthLogParser(year=2026).parse_file(SAMPLES / "auth.log"))
    journal = list(JournaldParser().parse_file(SAMPLES / "journald.json"))
    assert len(syslog) == len(journal) == 32
    assert [e.event.action for e in syslog] == [e.event.action for e in journal]
    assert _alerts(syslog) == _alerts(journal)
    assert _alerts(syslog)  # the sample does raise alerts


def test_crlf_xml_file() -> None:
    data = (
        "\r\n".join(['<?xml version="1.0"?>', "<Events>", xml(), "</Events>"]) + "\r\n"
    ).encode()
    stats = ParseStats()
    events = list(WindowsSecurityParser().parse(read_lines(io.BytesIO(data)), stats=stats))
    assert (len(events), stats.errors) == (1, 0)


@pytest.mark.parametrize(
    "record",
    [
        {"EventTime": "2026-10-24 14:00:00", "EventID": 4625, "SourceName": SEC},
        {"Id": 4625, "ProviderName": SEC, "TimeCreated": "/Date(1792850400000)/"},
        {"Event": {"System": {"EventID": 4625}}},
        {"winlog": {"event_id": "4625"}, "@timestamp": "2026-10-24T14:00:00Z"},
    ],
)
def test_every_json_layout_is_detected(record: dict[str, Any]) -> None:
    assert detect_format(iter_text_lines([json.dumps(record)])) == "windows_security"


def test_utf16_lines_are_bounded_and_describe_the_file(tmp_path: Path) -> None:
    from prohori.parsers.base import Utf16Lines, is_utf16

    path = tmp_path / "u16.json"
    path.write_bytes(b"\xff\xfe" + ("a" * 50 + "\r\nb\r\n").encode("utf-16-le"))
    assert is_utf16(path)
    stream = Utf16Lines(path)
    try:
        lines = list(read_lines(stream, max_length=10))
    finally:
        stream.close()
    assert lines[0].too_long
    assert lines[1].text == "b"
    assert stream.bytes == path.stat().st_size
    assert len(stream.hexdigest()) == 64
