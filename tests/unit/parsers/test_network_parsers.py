# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Tests for the network sensor parsers: Suricata ``eve.json`` and Zeek ``conn.log``."""

import io
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from prohori.parsers import (
    ParseStats,
    SuricataEveParser,
    ZeekConnParser,
    detect_format,
    get_parser,
    iter_text_lines,
    read_lines,
)
from prohori.parsers.zeek_conn import DEFAULT_FIELDS, MAX_FIELDS
from prohori.schema import Event

ROOT = Path(__file__).resolve().parents[3]
SAMPLES = ROOT / "samples" / "logs"
TAB = "\t"


def eve(kind: str = "alert", **overrides: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "timestamp": "2026-10-24T14:20:30.123456+0000",
        "flow_id": 1234567890123456,
        "in_iface": "eth0",
        "event_type": kind,
        "src_ip": "198.51.100.23",
        "src_port": 41020,
        "dest_ip": "192.0.2.10",
        "dest_port": 80,
        "proto": "TCP",
        "app_proto": "http",
    }
    if kind == "alert":
        record["alert"] = {
            "action": "allowed",
            "gid": 1,
            "signature_id": 9000001,
            "rev": 3,
            "signature": "PRH TEST Web shell upload",
            "category": "Web Application Attack",
            "severity": 1,
        }
    record.update(overrides)
    return record


def parse_eve(*records: object, **options: Any) -> tuple[list[Event], ParseStats]:
    lines = [r if isinstance(r, str) else json.dumps(r) for r in records]
    stats = ParseStats()
    parser = SuricataEveParser(**options)
    events = list(parser.parse(iter_text_lines(lines), source="eve.json", stats=stats))
    return events, stats


def zeek_row(**values: str) -> str:
    defaults = {
        "ts": "1792850400.250000",
        "uid": "CprhTest000000001",
        "id.orig_h": "192.0.2.21",
        "id.orig_p": "51000",
        "id.resp_h": "198.51.100.80",
        "id.resp_p": "443",
        "proto": "tcp",
        "service": "ssl",
        "duration": "1.500000",
        "orig_bytes": "812",
        "resp_bytes": "5300",
        "conn_state": "SF",
        "local_orig": "T",
        "local_resp": "F",
        "missed_bytes": "0",
        "history": "ShADadFf",
        "orig_pkts": "12",
        "orig_ip_bytes": "1292",
        "resp_pkts": "10",
        "resp_ip_bytes": "5700",
        "tunnel_parents": "-",
        "ip_proto": "6",
    }
    defaults.update(values)
    return TAB.join(defaults[f] for f in DEFAULT_FIELDS)


HEADER = [
    "#separator \\x09",
    "#set_separator\t,",
    "#empty_field\t(empty)",
    "#unset_field\t-",
    "#path\tconn",
    "#fields\t" + TAB.join(DEFAULT_FIELDS),
    "#types\t" + TAB.join(["string"] * len(DEFAULT_FIELDS)),
]


def parse_zeek(*lines: str) -> tuple[list[Event], ParseStats]:
    stats = ParseStats()
    events = list(ZeekConnParser().parse(iter_text_lines(lines), source="conn.log", stats=stats))
    return events, stats


def balanced(stats: ParseStats) -> bool:
    return stats.lines == stats.events + stats.skipped + stats.blank + stats.errors


class TestSuricataEve:
    def test_alert(self) -> None:
        (event,), _ = parse_eve(eve())
        assert event.timestamp == datetime(2026, 10, 24, 14, 20, 30, 123456, tzinfo=UTC)
        assert (event.log_source, event.event.action, event.event.category) == (
            "suricata",
            "ids.alert",
            "network",
        )
        assert event.event.severity == "high"
        assert event.event.reason == "PRH TEST Web shell upload"
        assert str(event.source.ip) == "198.51.100.23"
        assert event.extra["destination_ip"] == "192.0.2.10"
        assert event.extra["destination_port"] == 80
        assert event.extra["source_port"] == 41020
        assert event.extra["transport"] == "tcp"
        assert event.extra["signature_id"] == 9000001
        assert event.extra["signature_rev"] == 3
        assert event.extra["alert_action"] == "allowed"
        assert event.extra["flow_id"] == "1234567890123456"

    @pytest.mark.parametrize(
        ("severity", "expected"),
        [(1, "high"), (2, "medium"), (3, "low"), (4, "low"), (255, "low"), (None, "low")],
    )
    def test_severity_mapping(self, severity: int | None, expected: str) -> None:
        record = eve()
        record["alert"]["severity"] = severity
        (event,), _ = parse_eve(record)
        assert event.event.severity == expected

    def test_mitre_metadata_is_kept(self) -> None:
        record = eve()
        record["alert"]["metadata"] = {
            "mitre_technique_id": ["T1190", "T1505.003"],
            "mitre_tactic_id": ["TA0001"],
            "created_at": ["2026_01_01"],
        }
        (event,), _ = parse_eve(record)
        assert event.extra["mitre_technique_id"] == "T1190,T1505.003"
        assert event.extra["mitre_tactic_id"] == "TA0001"
        assert "created_at" not in event.extra

    def test_http_becomes_a_web_request(self) -> None:
        record = eve(
            "http",
            http={
                "hostname": "shop.example",
                "url": "/search?q=%27+or+1%3D1",
                "http_user_agent": "sqlmap/1.8",
                "http_method": "get",
                "protocol": "HTTP/1.1",
                "status": "404",
                "length": 153,
                "http_refer": "https://shop.example/",
            },
        )
        (event,), _ = parse_eve(record)
        assert (event.event.action, event.event.category) == ("web.request", "web")
        assert event.event.outcome == "failure"
        assert (event.http.method, event.http.path, event.http.status) == ("GET", "/search", 404)
        assert event.http.bytes == 153
        assert event.extra["query"] == "q=%27+or+1%3D1"
        assert event.extra["http_host"] == "shop.example"
        assert event.user_agent == "sqlmap/1.8"

    def test_keep_query(self) -> None:
        record = eve("http", http={"url": "/a?b=c", "status": 200})
        (event,), _ = parse_eve(record, keep_query=True)
        assert event.http.path == "/a?b=c"
        assert event.event.outcome == "success"
        assert "query" not in event.extra

    def test_out_of_range_http_status_is_dropped(self) -> None:
        (event,), _ = parse_eve(eve("http", http={"url": "/", "status": 999}))
        assert event.http.status is None
        assert event.event.outcome == "unknown"

    def test_dns_version_2_and_3(self) -> None:
        v2 = eve(
            "dns", dns={"version": 2, "type": "query", "rrname": "Updates.Example", "rrtype": "A"}
        )
        v3 = eve(
            "dns",
            dns={
                "version": 3,
                "type": "answer",
                "rcode": "NXDOMAIN",
                "queries": [{"rrname": "missing.example", "rrtype": "AAAA"}],
            },
        )
        (first, second), _ = parse_eve(v2, v3)
        assert first.event.action == "network.dns"
        assert (first.extra["dns_question"], first.extra["dns_type"]) == ("Updates.Example", "A")
        assert first.extra["dns_domain"] == "updates.example"
        assert (second.extra["dns_question"], second.extra["dns_rcode"]) == (
            "missing.example",
            "NXDOMAIN",
        )

    def test_tls_and_ssh(self) -> None:
        tls = eve(
            "tls",
            tls={"sni": "Updates.Example", "version": "TLS 1.3", "ja3": {"hash": "abc"}},
        )
        ssh = eve(
            "ssh",
            ssh={
                "client": {"proto_version": "2.0", "software_version": "libssh_0.9.6"},
                "server": {"proto_version": "2.0", "software_version": "OpenSSH_9.6"},
            },
        )
        (first, second), _ = parse_eve(tls, ssh)
        assert first.extra["tls_domain"] == "updates.example"
        assert first.extra["ja3_hash"] == "abc"
        assert second.event.action == "network.ssh"
        assert second.extra["ssh_client_software"] == "libssh_0.9.6"
        assert second.extra["ssh_server_protocol"] == "2.0"

    def test_flow_is_dated_at_its_end(self) -> None:
        record = eve(
            "flow",
            flow={
                "pkts_toserver": 12,
                "pkts_toclient": 10,
                "bytes_toserver": 1292,
                "bytes_toclient": 5700,
                "start": "2026-10-24T13:00:00.000000+0000",
                "end": "2026-10-24T14:00:30.500000+0000",
                "age": 3630,
                "state": "closed",
                "reason": "timeout",
            },
        )
        (event,), _ = parse_eve(record)
        assert event.event.action == "network.flow"
        assert event.timestamp == datetime(2026, 10, 24, 14, 0, 30, 500000, tzinfo=UTC)
        assert event.extra["duration"] == 3630.5
        assert event.extra["start_time"] == "2026-10-24T13:00:00Z"
        assert (event.extra["bytes_out"], event.extra["bytes_in"]) == (1292, 5700)
        assert (event.extra["packets_out"], event.extra["packets_in"]) == (12, 10)

    def test_flow_without_times_uses_age(self) -> None:
        (event,), _ = parse_eve(eve("flow", flow={"age": 42}))
        assert event.extra["duration"] == 42.0
        assert event.timestamp == datetime(2026, 10, 24, 14, 20, 30, 123456, tzinfo=UTC)

    def test_other_event_types_are_skipped(self) -> None:
        events, stats = parse_eve(eve("stats"), eve("fileinfo"), eve("anomaly"), eve("netflow"))
        assert (events, stats.skipped) == ([], 4)

    @pytest.mark.parametrize(
        "timestamp",
        ["2026-10-24T20:20:30.123456+0600", "2026-10-24T14:20:30.123456Z"],
    )
    def test_timestamp_offsets(self, timestamp: str) -> None:
        (event,), _ = parse_eve(eve(timestamp=timestamp))
        assert event.timestamp == datetime(2026, 10, 24, 14, 20, 30, 123456, tzinfo=UTC)

    @pytest.mark.parametrize(
        ("record", "reason"),
        [
            ("not json", "invalid JSON"),
            ("[1, 2]", "not an object"),
            (eve(event_type=None), "event_type"),
            (eve(timestamp="2026-10-24T14:20:30"), "timezone"),
            (eve(timestamp="yesterday"), "timestamp"),
            (eve(src_ip="not-an-ip"), "src_ip"),
            (eve(dest_ip=None), "dest_ip"),
            (eve(dest_port=70000), "dest_port"),
            (eve(src_port=-1), "src_port"),
            (eve(src_port=True), "src_port"),
            (eve(alert="x"), "not an object"),
            (eve(alert={"severity": 1}), "signature"),
            (eve("flow", flow={"age": -5}), "flow.age"),
            (eve("flow", flow={"age": 10**9}), "duration"),
            (eve("flow", flow={"start": "never"}), "flow.start"),
            (eve("flow", flow={"bytes_toserver": "lots"}), "bytes_toserver"),
            (eve(flow_id={"nested": 1}), "scalar"),
        ],
    )
    def test_malformed_records_are_counted(self, record: object, reason: str) -> None:
        events, stats = parse_eve(record)
        assert (events, stats.errors) == ([], 1)
        assert reason in stats.error_examples[0].reason

    def test_control_characters_are_removed(self) -> None:
        record = eve()
        record["alert"]["signature"] = "evil\u001b[31m‮ signature"
        (event,), _ = parse_eve(record)
        assert event.event.reason == "evil signature"

    def test_ipv6_and_mapped_addresses(self) -> None:
        (event,), _ = parse_eve(eve(src_ip="::ffff:198.51.100.23", dest_ip="2001:db8::10"))
        assert str(event.source.ip) == "198.51.100.23"
        assert event.extra["destination_ip"] == "2001:db8::10"

    def test_sample_file(self) -> None:
        stats = ParseStats()
        events = list(SuricataEveParser().parse_file(SAMPLES / "suricata-eve.json", stats=stats))
        assert (stats.errors, stats.skipped, len(events)) == (0, 1, 21)
        actions = {e.event.action for e in events}
        assert actions == {
            "ids.alert",
            "web.request",
            "network.dns",
            "network.tls",
            "network.ssh",
            "network.flow",
        }

    @settings(max_examples=300)
    @given(st.text(max_size=300))
    def test_arbitrary_text_never_raises(self, text: str) -> None:
        _, stats = parse_eve(*text.split("\n"))
        assert balanced(stats)

    @settings(max_examples=300)
    @given(
        st.fixed_dictionaries(
            {
                "event_type": st.sampled_from(["alert", "http", "dns", "tls", "ssh", "flow"]),
                "timestamp": st.sampled_from(["2026-10-24T14:20:30+0000", "x", 5]),
                "src_ip": st.sampled_from(["198.51.100.1", "::1", "", None]),
                "dest_ip": st.sampled_from(["192.0.2.1", "nope"]),
            },
            optional={
                key: st.recursive(
                    st.none() | st.booleans() | st.integers() | st.floats() | st.text(max_size=8),
                    lambda c: (
                        st.lists(c, max_size=3)
                        | st.dictionaries(st.text(max_size=8), c, max_size=3)
                    ),
                    max_leaves=10,
                )
                for key in ("alert", "http", "dns", "tls", "ssh", "flow", "dest_port")
            },
        )
    )
    def test_arbitrary_records_never_raise(self, record: dict[str, Any]) -> None:
        _, stats = parse_eve(json.dumps(record))
        assert stats.lines == 1
        assert balanced(stats)


class TestZeekConn:
    def test_tsv_with_header(self) -> None:
        events, stats = parse_zeek(*HEADER, zeek_row(), "#close\t2026-10-24-14-30-00")
        assert (stats.events, stats.skipped, stats.errors) == (1, len(HEADER) + 1, 0)
        (event,) = events
        assert (event.log_source, event.event.action, event.event.category) == (
            "zeek",
            "network.flow",
            "network",
        )
        assert event.event.outcome == "success"
        assert event.timestamp == datetime(2026, 10, 24, 14, 0, 1, 750000, tzinfo=UTC)
        assert event.extra["start_time"] == "2026-10-24T14:00:00.250000Z"
        assert event.extra["duration"] == 1.5
        assert event.extra["direction"] == "outbound"
        assert event.extra["destination_ip"] == "198.51.100.80"
        assert event.extra["destination_port"] == 443
        assert (event.extra["bytes_out"], event.extra["bytes_in"]) == (812, 5300)
        assert event.extra["uid"] == "CprhTest000000001"
        assert "\t" not in event.raw

    def test_columns_follow_the_header(self) -> None:
        fields = ["id.resp_p", "id.resp_h", "ts", "id.orig_h", "proto", "community_id"]
        lines = [
            "#fields\t" + TAB.join(fields),
            TAB.join(["22", "192.0.2.10", "1792850400", "203.0.113.66", "tcp", "1:abc="]),
        ]
        (event,), stats = parse_zeek(*lines)
        assert stats.errors == 0
        assert event.extra["destination_port"] == 22
        assert event.extra["community_id"] == "1:abc="
        assert event.event.outcome == "unknown"
        assert "duration" not in event.extra
        assert event.timestamp == datetime(2026, 10, 24, 14, 0, tzinfo=UTC)

    @pytest.mark.parametrize(
        ("state", "outcome"),
        [
            ("SF", "success"),
            ("RSTO", "success"),
            ("S0", "failure"),
            ("REJ", "failure"),
            ("SH", "failure"),
            ("OTH", "unknown"),
            ("-", "unknown"),
        ],
    )
    def test_connection_state_outcome(self, state: str, outcome: str) -> None:
        (event,), _ = parse_zeek(*HEADER, zeek_row(conn_state=state))
        assert event.event.outcome == outcome

    @pytest.mark.parametrize(
        ("local_orig", "local_resp", "direction"),
        [
            ("T", "F", "outbound"),
            ("F", "T", "inbound"),
            ("T", "T", "internal"),
            ("F", "F", "external"),
            ("-", "-", None),
            ("T", "-", None),
        ],
    )
    def test_direction(self, local_orig: str, local_resp: str, direction: str | None) -> None:
        (event,), _ = parse_zeek(*HEADER, zeek_row(local_orig=local_orig, local_resp=local_resp))
        assert event.extra.get("direction") == direction

    def test_unset_and_empty_values(self) -> None:
        row = zeek_row(service="(empty)", duration="-", orig_bytes="-", history="-")
        (event,), _ = parse_zeek(*HEADER, row)
        assert "app_protocol" not in event.extra
        assert "duration" not in event.extra
        assert "bytes_out" not in event.extra
        assert event.timestamp == datetime(2026, 10, 24, 14, 0, 0, 250000, tzinfo=UTC)

    def test_escapes_are_decoded_and_sanitised(self) -> None:
        (event,), _ = parse_zeek(*HEADER, zeek_row(service="ht\\x1b[31mtp\\x2c2"))
        assert event.extra["app_protocol"] == "http,2"  # the ANSI sequence is removed whole

    def test_lines_before_a_header_use_the_default_layout(self) -> None:
        short = TAB.join(zeek_row().split(TAB)[:-1])  # Zeek before 7.1: no ip_proto
        events, stats = parse_zeek(zeek_row(), short, "1792850400\tC1\t192.0.2.1")
        assert (len(events), stats.errors) == (2, 1)
        assert "before a #fields header" in stats.error_examples[0].reason

    def test_wrong_column_count_after_a_header(self) -> None:
        _, stats = parse_zeek(*HEADER, zeek_row() + "\textra")
        assert stats.errors == 1
        assert "columns" in stats.error_examples[0].reason

    def test_other_logs_are_skipped(self) -> None:
        dns = [h.replace("#path\tconn", "#path\tdns") for h in HEADER]
        events, stats = parse_zeek(*dns, zeek_row())
        assert (events, stats.errors) == ([], 0)
        assert stats.skipped == len(dns) + 1

    @pytest.mark.parametrize(
        "header",
        [
            "#fields\t" + TAB.join(f"f{i}" for i in range(MAX_FIELDS + 1)),
            "#fields\tuid\tid.orig_h",  # no ts
            "#fields\tts\tid.orig_h\tid.resp_h\tts",  # duplicate
            "#fields\tts\tid.orig_h\tid.resp_h\tbad name",
            "#separator ab",
        ],
    )
    def test_invalid_headers_are_errors(self, header: str) -> None:
        _, stats = parse_zeek(header)
        assert stats.errors == 1

    def test_an_invalid_header_stops_later_lines(self) -> None:
        events, stats = parse_zeek("#fields\tuid", "1792850400\tC1\t192.0.2.1")
        assert (events, stats.errors) == ([], 2)

    def test_custom_separator(self) -> None:
        lines = [
            "#separator \\x2c",
            "#fields,ts,id.orig_h,id.resp_h,id.resp_p",
            "1792850400,192.0.2.1,192.0.2.2,80",
        ]
        (event,), stats = parse_zeek(*lines)
        assert stats.errors == 0
        assert event.extra["destination_port"] == 80

    @pytest.mark.parametrize(
        ("values", "reason"),
        [
            ({"ts": "yesterday"}, "ts"),
            ({"ts": "1e300"}, "ts"),
            ({"duration": "-1"}, "duration"),
            ({"duration": "nan"}, "duration"),
            ({"duration": "99999999999"}, "duration"),
            ({"id.orig_h": "not-an-ip"}, "id.orig_h"),
            ({"id.resp_p": "65536"}, "id.resp_p"),
            ({"orig_bytes": "12abc"}, "orig_bytes"),
            ({"local_orig": "yes"}, "local_orig"),
        ],
    )
    def test_malformed_values_are_counted(self, values: dict[str, str], reason: str) -> None:
        events, stats = parse_zeek(*HEADER, zeek_row(**values))
        assert (events, stats.errors) == ([], 1)
        assert reason in stats.error_examples[0].reason

    def test_json_flat_and_nested(self) -> None:
        flat = {
            "ts": 1792850400.25,
            "uid": "CprhJson1",
            "id.orig_h": "192.0.2.21",
            "id.orig_p": 51000,
            "id.resp_h": "198.51.100.80",
            "id.resp_p": 443,
            "proto": "tcp",
            "duration": 2.0,
            "orig_bytes": 10,
            "conn_state": "S0",
            "local_orig": True,
            "local_resp": False,
        }
        nested = {
            "ts": "2026-10-24T14:00:00.250000Z",
            "uid": "CprhJson2",
            "id": {"orig_h": "192.0.2.21", "orig_p": 1, "resp_h": "2001:db8::1", "resp_p": 53},
            "proto": "udp",
            "conn_state": "SF",
        }
        (first, second), stats = parse_zeek(json.dumps(flat), json.dumps(nested))
        assert stats.errors == 0
        assert first.timestamp == datetime(2026, 10, 24, 14, 0, 2, 250000, tzinfo=UTC)
        assert (first.event.outcome, first.extra["direction"]) == ("failure", "outbound")
        assert second.extra["destination_ip"] == "2001:db8::1"
        assert second.extra["transport"] == "udp"

    def test_json_from_other_logs_is_skipped(self) -> None:
        events, stats = parse_zeek(json.dumps({"_path": "dns", "ts": 1, "id.orig_h": "x"}))
        assert (events, stats.skipped) == ([], 1)

    def test_long_connection_is_dated_at_its_end(self) -> None:
        start = datetime(2026, 10, 24, 5, 0, tzinfo=UTC)
        row = zeek_row(ts=f"{start.timestamp():.6f}", duration="33312.25")
        (event,), _ = parse_zeek(*HEADER, row)
        assert event.timestamp == start + timedelta(seconds=33312.25)

    def test_sample_files(self) -> None:
        for name, count in (("zeek-conn.log", 42), ("zeek-conn.json", 9)):
            stats = ParseStats()
            events = list(ZeekConnParser().parse_file(SAMPLES / name, stats=stats))
            assert (stats.errors, len(events)) == (0, count), name

    def test_crlf_file(self) -> None:
        data = "\r\n".join([*HEADER, zeek_row()]).encode() + b"\r\n"
        stats = ParseStats()
        events = list(ZeekConnParser().parse(read_lines(io.BytesIO(data)), stats=stats))
        assert (len(events), stats.errors) == (1, 0)

    def test_state_is_reset_between_inputs(self) -> None:
        parser = ZeekConnParser()
        list(parser.parse(iter_text_lines(["#path\tdns"])))
        assert len(list(parser.parse(iter_text_lines([zeek_row()])))) == 1

    @settings(max_examples=300)
    @given(
        st.lists(
            st.text(alphabet=st.sampled_from("#\t ,.-:Tf0123456789abcdefx\\"), max_size=60),
            max_size=8,
        )
    )
    def test_arbitrary_tsv_never_raises(self, lines: list[str]) -> None:
        _, stats = parse_zeek(*HEADER[:6], *lines)
        assert balanced(stats)

    @settings(max_examples=300)
    @given(st.text(max_size=300))
    def test_arbitrary_text_never_raises(self, text: str) -> None:
        _, stats = parse_zeek(*text.split("\n"))
        assert balanced(stats)


class TestDetection:
    @pytest.mark.parametrize(
        ("name", "expected"),
        [
            ("suricata-eve.json", "suricata_eve"),
            ("zeek-conn.log", "zeek_conn"),
            ("zeek-conn.json", "zeek_conn"),
            ("app-security.jsonl", "app_json"),
            ("auth.log", "auth_log"),
            ("access.log", "access_log"),
        ],
    )
    def test_samples(self, name: str, expected: str) -> None:
        with (SAMPLES / name).open("rb") as stream:
            assert detect_format(read_lines(stream)) == expected

    def test_zeek_data_lines_without_a_header(self) -> None:
        assert detect_format(iter_text_lines([zeek_row(), zeek_row()])) == "zeek_conn"

    def test_registered(self) -> None:
        assert isinstance(get_parser("suricata_eve", keep_query=True), SuricataEveParser)
        assert isinstance(get_parser("zeek_conn"), ZeekConnParser)
