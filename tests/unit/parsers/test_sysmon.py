# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Tests for Sysmon events, 4688 process creation and the host-activity schema fields."""

import json
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from prohori.parsers import (
    FieldMapping,
    GenericJsonParser,
    ParseStats,
    SysmonParser,
    WindowsSecurityParser,
    iter_text_lines,
)
from prohori.parsers.sysmon import base_name, sha256_of, split_user
from prohori.schema import FIELD_PATHS, Event, from_json, get_field, is_valid_path, to_json

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples" / "logs"
SYSMON = "Microsoft-Windows-Sysmon"
CHANNEL = "Microsoft-Windows-Sysmon/Operational"
NS = "http://schemas.microsoft.com/win/2004/08/events/event"
PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"

CREATED = {
    "RuleName": "-",
    "ProcessGuid": "{94f748d5-0001-6a1a-0000-001000001118}",
    "ProcessId": "4376",
    "Image": PS,
    "CommandLine": "powershell.exe -nop -enc VwByAGkAdABlAC0ATwB1AHQAcAB1AHQA",
    "CurrentDirectory": "C:\\Users\\amina\\",
    "User": "CORP\\amina",
    "IntegrityLevel": "Medium",
    "Hashes": "SHA1="
    + "A" * 40
    + ",MD5="
    + "B" * 32
    + ",SHA256="
    + "C" * 64
    + ",IMPHASH="
    + "D" * 32,
    "ParentProcessGuid": "{94f748d5-0001-6a1a-0000-001000001112}",
    "ParentProcessId": "4370",
    "ParentImage": WORD,
    "ParentCommandLine": f'"{WORD}" /n invoice.docm',
}


def beat(
    event_id: int, data: dict[str, str], channel: str = CHANNEL, provider: str = SYSMON
) -> str:
    return json.dumps(
        {
            "@timestamp": "2026-10-24T09:00:00.000Z",
            "winlog": {
                "channel": channel,
                "computer_name": "WS01.corp.example",
                "event_id": str(event_id),
                "provider_name": provider,
                "record_id": "5",
                "event_data": data,
            },
        }
    )


def parse(*lines: str, parser: Any = None) -> tuple[list[Event], ParseStats]:
    stats = ParseStats()
    chosen = parser or WindowsSecurityParser()
    events = list(chosen.parse(iter_text_lines(lines), source="sysmon.json", stats=stats))
    return events, stats


class TestSysmonMapping:
    def test_process_creation(self) -> None:
        (event,), _ = parse(beat(1, CREATED))
        assert (event.log_source, event.event.action, event.event.category) == (
            "sysmon",
            "process.created",
            "process",
        )
        assert event.process is not None
        assert (event.process.pid, event.process.name, event.process.executable) == (
            4376,
            "powershell.exe",
            PS,
        )
        assert event.process.hash == "c" * 64
        assert event.process.integrity_level == "medium"
        assert event.process.parent is not None
        assert (event.process.parent.pid, event.process.parent.name) == (4370, "WINWORD.EXE")
        assert event.user.name == "amina"
        assert event.extra["user_domain"] == "CORP"
        assert event.host == "ws01.corp.example"
        assert get_field(event, "process.parent.name") == "WINWORD.EXE"

    def test_network_connection(self) -> None:
        data = {
            "ProcessId": "4376",
            "Image": PS,
            "Protocol": "tcp",
            "SourceIp": "192.0.2.41",
            "SourcePort": "51300",
            "DestinationIp": "203.0.113.80",
            "DestinationHostname": "Updates.Example.Net",
            "DestinationPort": "443",
        }
        (event,), _ = parse(beat(3, data))
        assert event.event.action == "network.connection"
        assert get_field(event, "destination.ip") == "203.0.113.80"
        assert get_field(event, "destination.port") == 443
        assert get_field(event, "destination.domain") == "updates.example.net"
        assert str(event.source.ip) == "192.0.2.41"
        assert event.extra["transport"] == "tcp"
        assert get_field(event, "process.hash") is None

    @pytest.mark.parametrize(
        ("event_id", "data", "action", "category", "field", "value"),
        [
            (
                7,
                {"Image": PS, "ImageLoaded": "C:\\Windows\\System32\\dbghelp.dll"},
                "process.image_loaded",
                "process",
                "file.name",
                "dbghelp.dll",
            ),
            (
                8,
                {
                    "SourceImage": PS,
                    "SourceProcessId": "1",
                    "TargetImage": "C:\\Windows\\explorer.exe",
                },
                "process.remote_thread_created",
                "process",
                "extra.target_name",
                "explorer.exe",
            ),
            (
                10,
                {
                    "SourceImage": PS,
                    "TargetImage": "C:\\Windows\\system32\\lsass.exe",
                    "GrantedAccess": "0x1010",
                },
                "process.accessed",
                "process",
                "extra.target_name",
                "lsass.exe",
            ),
            (
                11,
                {"Image": PS, "TargetFilename": "C:\\Users\\Public\\A.EXE"},
                "file.created",
                "file",
                "file.extension",
                "exe",
            ),
            (
                12,
                {"EventType": "CreateKey", "Image": PS, "TargetObject": "HKLM\\Software\\X"},
                "registry.key_created",
                "registry",
                "registry.path",
                "HKLM\\Software\\X",
            ),
            (
                12,
                {"EventType": "DeleteValue", "Image": PS, "TargetObject": "HKLM\\Software\\X\\v"},
                "registry.value_deleted",
                "registry",
                "registry.path",
                "HKLM\\Software\\X\\v",
            ),
            (
                13,
                {
                    "EventType": "SetValue",
                    "Image": PS,
                    "TargetObject": "HKLM\\S\\Svc\\ImagePath",
                    "Details": "C:\\x.exe",
                },
                "registry.value_set",
                "registry",
                "registry.value",
                "ImagePath",
            ),
            (
                14,
                {
                    "EventType": "RenameKey",
                    "Image": PS,
                    "TargetObject": "HKLM\\a",
                    "NewName": "HKLM\\b",
                },
                "registry.renamed",
                "registry",
                "extra.new_name",
                "HKLM\\b",
            ),
            (
                22,
                {"Image": PS, "QueryName": "odd-NAME.example", "QueryStatus": "0"},
                "dns.query",
                "dns",
                "dns.question",
                "odd-NAME.example",
            ),
            (
                23,
                {"Image": PS, "TargetFilename": "C:\\a.dmp", "Hashes": "SHA256=" + "e" * 64},
                "file.deleted",
                "file",
                "extra.archived",
                "true",
            ),
            (
                26,
                {"Image": PS, "TargetFilename": "C:\\a.dmp"},
                "file.deleted",
                "file",
                "extra.archived",
                "false",
            ),
        ],
    )
    def test_every_event_id(
        self,
        event_id: int,
        data: dict[str, str],
        action: str,
        category: str,
        field: str,
        value: object,
    ) -> None:
        (event,), stats = parse(beat(event_id, data))
        assert stats.errors == 0
        assert (event.event.action, event.event.category) == (action, category)
        assert get_field(event, field) == value
        assert get_field(event, "process.hash") is None  # Hashes describe a file here

    def test_unmapped_sysmon_ids_are_skipped(self) -> None:
        events, stats = parse(beat(6, {"ImageLoaded": "x.sys"}), beat(255, {}))
        assert (events, stats.skipped) == ([], 2)

    def test_missing_fields_are_unset_not_errors(self) -> None:
        (event,), stats = parse(beat(1, {"Image": PS}))
        assert stats.errors == 0
        assert event.process is not None
        assert event.process.command_line is None
        assert event.process.parent is not None
        assert event.process.parent.name is None

    @pytest.mark.parametrize(
        ("data", "reason"),
        [
            ({**CREATED, "ProcessId": "abc"}, "ProcessId"),
            ({**CREATED, "ProcessId": "99999999999"}, "out of range"),
            ({"Image": PS, "DestinationIp": "203.0.113.80", "DestinationPort": "70000"}, "port"),
        ],
    )
    def test_malformed_values(self, data: dict[str, str], reason: str) -> None:
        event_id = 3 if "DestinationIp" in data else 1
        events, stats = parse(beat(event_id, data))
        assert (events, stats.errors) == ([], 1)
        assert reason in stats.error_examples[0].reason

    def test_xml_and_channel_without_provider(self) -> None:
        values = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in CREATED.items())
        line = (
            f'<Event xmlns="{NS}"><System><Provider Name="{SYSMON}"/><EventID>1</EventID>'
            '<TimeCreated SystemTime="2026-10-24T09:00:00.0000000Z"/>'
            f"<Channel>{CHANNEL}</Channel><Computer>WS01</Computer></System>"
            f"<EventData>{values.replace('&', '&amp;')}</EventData></Event>"
        )
        nxlog = json.dumps(
            {"EventTime": "2026-10-24 09:00:00", "EventID": 1, "Channel": CHANNEL, **CREATED}
        )
        events, stats = parse(line, nxlog)
        assert stats.errors == 0
        assert [e.event.action for e in events] == ["process.created"] * 2

    def test_get_winevent_sysmon_needs_names(self) -> None:
        record = {
            "Id": 1,
            "ProviderName": SYSMON,
            "TimeCreated": "/Date(1792850400000)/",
            "Properties": [{"Value": v} for v in CREATED.values()],
        }
        events, stats = parse(json.dumps(record))
        assert (events, stats.errors) == ([], 1)
        assert "ToXml()" in stats.error_examples[0].reason

    def test_sysmon_parser_reads_only_sysmon(self) -> None:
        security = beat(
            4625,
            {"TargetUserName": "bob", "IpAddress": "203.0.113.5"},
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
        )
        events, stats = parse(beat(1, CREATED), security, parser=SysmonParser())
        assert [e.event.action for e in events] == ["process.created"]
        assert stats.skipped == 1
        both, _ = parse(beat(1, CREATED), security)
        assert [e.log_source for e in both] == ["sysmon", "windows-security"]

    def test_sample_file(self) -> None:
        stats = ParseStats()
        events = list(
            WindowsSecurityParser().parse_file(SAMPLES / "windows-sysmon.jsonl", stats=stats)
        )
        assert (stats.errors, stats.skipped, len(events)) == (0, 1, 21)

    @settings(max_examples=300)
    @given(
        st.sampled_from([1, 3, 7, 8, 10, 11, 12, 13, 14, 22, 23, 26]),
        st.dictionaries(
            st.sampled_from(
                [
                    *CREATED,
                    "DestinationIp",
                    "DestinationPort",
                    "TargetObject",
                    "QueryName",
                    "SourceImage",
                    "TargetImage",
                    "EventType",
                    "Details",
                    "TargetFilename",
                ]
            ),
            st.text(max_size=30),
            max_size=12,
        ),
    )
    def test_arbitrary_values_never_raise(self, event_id: int, data: dict[str, str]) -> None:
        _, stats = parse(beat(event_id, data))
        assert stats.lines == stats.events + stats.skipped + stats.blank + stats.errors == 1


DATA_4688 = {
    "SubjectUserSid": "S-1-5-21-1-2-3-1106",
    "SubjectUserName": "amina",
    "SubjectDomainName": "CORP",
    "SubjectLogonId": "0x2d41f",
    "NewProcessId": "0x1118",
    "NewProcessName": PS,
    "TokenElevationType": "%%1938",
    "ProcessId": "0x1112",
    "CommandLine": "powershell.exe -enc AAAA",
    "TargetUserSid": "S-1-0-0",
    "TargetUserName": "-",
    "TargetDomainName": "-",
    "TargetLogonId": "0x0",
    "ParentProcessName": WORD,
    "MandatoryLabel": "S-1-16-8192",
}


class TestProcessCreation4688:
    def test_named_fields(self) -> None:
        line = beat(
            4688, DATA_4688, channel="Security", provider="Microsoft-Windows-Security-Auditing"
        )
        (event,), _ = parse(line)
        assert (event.log_source, event.event.action) == ("windows-security", "process.created")
        assert event.process is not None
        assert (event.process.pid, event.process.name) == (0x1118, "powershell.exe")
        assert event.process.integrity_level == "medium"
        assert event.process.parent is not None
        assert (event.process.parent.pid, event.process.parent.name) == (0x1112, "WINWORD.EXE")
        assert event.user.name == "amina"
        assert event.extra["elevation_type"] == "limited"

    def test_get_winevent_positional(self) -> None:
        record = {
            "Id": 4688,
            "ProviderName": "Microsoft-Windows-Security-Auditing",
            "TimeCreated": "/Date(1792850400000)/",
            "Properties": [{"Value": v} for v in DATA_4688.values()],
        }
        (event,), _ = parse(json.dumps(record))
        assert get_field(event, "process.command_line") == "powershell.exe -enc AAAA"


class TestSchemaFields:
    def test_field_paths_include_nested_groups(self) -> None:
        for path in (
            "process.parent.name",
            "file.extension",
            "registry.data",
            "destination.domain",
            "dns.question",
        ):
            assert path in FIELD_PATHS
            assert is_valid_path(path)
        assert "process.parent" not in FIELD_PATHS

    def test_unset_groups_are_left_out_of_the_json(self) -> None:
        event = Event.model_validate(
            {
                "timestamp": "2026-10-24T09:00:00Z",
                "log_source": "x",
                "event": {"action": "a.b", "category": "web"},
                "raw": "x",
            }
        )
        data = json.loads(to_json(event))
        assert not {"process", "file", "registry", "destination", "dns"} & data.keys()
        assert get_field(event, "process.parent.name") is None

    def test_groups_round_trip(self) -> None:
        event = Event.model_validate(
            {
                "timestamp": "2026-10-24T09:00:00Z",
                "log_source": "x",
                "event": {"action": "process.created", "category": "process"},
                "process": {"pid": 1, "name": "a.exe", "parent": {"name": "b.exe"}},
                "destination": {"ip": "203.0.113.1", "port": 443},
                "raw": "x",
            }
        )
        again = from_json(Event, to_json(event))
        assert again == event
        assert "file" not in json.loads(to_json(event))

    def test_hash_must_be_sha256(self) -> None:
        with pytest.raises(ValueError, match="hash"):
            Event.model_validate(
                {
                    "timestamp": "2026-10-24T09:00:00Z",
                    "log_source": "x",
                    "event": {"action": "a", "category": "process"},
                    "process": {"hash": "not-a-hash"},
                    "raw": "x",
                }
            )

    def test_generic_json_maps_nested_fields(self) -> None:
        mapping = {
            "log_source": "edr",
            "timestamp": {"field": "t"},
            "fields": {
                "event.action": "kind",
                "process.name": "proc.name",
                "process.parent.name": "proc.parent",
                "process.pid": "proc.pid",
                "destination.port": "dport",
            },
            "constants": {"event.category": "process"},
        }
        parser = GenericJsonParser(mapping=FieldMapping.model_validate(mapping))
        line = json.dumps(
            {
                "t": "2026-10-24T09:00:00Z",
                "kind": "process.created",
                "dport": 443,
                "proc": {"name": "cmd.exe", "parent": "winword.exe", "pid": 7},
            }
        )
        (event,) = list(parser.parse(iter_text_lines([line])))
        assert get_field(event, "process.parent.name") == "winword.exe"
        assert get_field(event, "process.pid") == 7
        assert get_field(event, "destination.port") == 443


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("C:\\Windows\\cmd.exe", "cmd.exe"),
        ("/usr/bin/bash", "bash"),
        ("C:\\dir\\", None),
        (None, None),
    ],
)
def test_base_name(text: str | None, expected: str | None) -> None:
    assert base_name(text) == expected


def test_helpers() -> None:
    assert sha256_of("SHA1=AA,SHA256=" + "F" * 64) == "f" * 64
    assert sha256_of("MD5=AA") is None
    assert split_user("CORP\\amina") == ("amina", "CORP")
    assert split_user("amina") == ("amina", None)
