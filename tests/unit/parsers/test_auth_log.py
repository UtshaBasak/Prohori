"""Tests for the auth.log / secure parser."""

import io
import os
import tracemalloc
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from prohori.parsers import AuthLogParser, ParseStats, iter_text_lines, read_lines
from prohori.schema import Event, EventCategory, Outcome

SAMPLES = Path(__file__).resolve().parents[3] / "samples" / "logs"
HDR = "Oct 24 13:50:02 web01"


def parse(*lines: str, **options: object) -> tuple[list[Event], ParseStats]:
    stats = ParseStats()
    parser = AuthLogParser(**{"year": 2026, **options})  # type: ignore[arg-type]
    events = list(parser.parse(iter_text_lines(lines), source="test.log", stats=stats))
    return events, stats


def one(line: str, **options: object) -> Event:
    events, stats = parse(line, **options)
    assert len(events) == 1, stats.as_dict()
    return events[0]


# (message after the header, action, outcome, reason, user, ip, category)
SSHD_CASES = [
    (
        "sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2",
        "ssh.login.failure",
        Outcome.FAILURE,
        "bad_password",
        "root",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Failed password for invalid user admin from 203.0.113.7 port 51234 ssh2",
        "ssh.login.failure",
        Outcome.FAILURE,
        "unknown_user",
        "admin",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Failed publickey for git from 203.0.113.7 port 22 ssh2: RSA SHA256:abc",
        "ssh.login.failure",
        Outcome.FAILURE,
        "bad_key",
        "git",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Failed none for invalid user  from 203.0.113.7 port 22 ssh2",
        "ssh.login.failure",
        Outcome.FAILURE,
        "unknown_user",
        "",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Failed keyboard-interactive/pam for bob from 203.0.113.7 port 22 ssh2",
        "ssh.login.failure",
        Outcome.FAILURE,
        "bad_password",
        "bob",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Failed hostbased for bob from 203.0.113.7 port 22 ssh2",
        "ssh.login.failure",
        Outcome.FAILURE,
        "auth_failed",
        "bob",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Accepted password for alice from 192.0.2.10 port 50500 ssh2",
        "ssh.login.success",
        Outcome.SUCCESS,
        None,
        "alice",
        "192.0.2.10",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Accepted publickey for deploy from 2001:db8::42 port 60022 ssh2: "
        "ED25519 SHA256:x",
        "ssh.login.success",
        Outcome.SUCCESS,
        None,
        "deploy",
        "2001:db8::42",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Invalid user oracle from 198.51.100.77 port 41000",
        "ssh.invalid_user",
        Outcome.FAILURE,
        "unknown_user",
        "oracle",
        "198.51.100.77",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Invalid user oracle from 198.51.100.77",
        "ssh.invalid_user",
        Outcome.FAILURE,
        "unknown_user",
        "oracle",
        "198.51.100.77",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: error: maximum authentication attempts exceeded for root from 203.0.113.7 "
        "port 22 ssh2 [preauth]",
        "ssh.auth.too_many_failures",
        Outcome.FAILURE,
        "too_many_failures",
        "root",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: error: maximum authentication attempts exceeded for invalid user test from "
        "203.0.113.7 port 22 ssh2 [preauth]",
        "ssh.auth.too_many_failures",
        Outcome.FAILURE,
        "unknown_user",
        "test",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Disconnecting authenticating user root 203.0.113.7 port 22: "
        "Too many authentication failures [preauth]",
        "ssh.auth.too_many_failures",
        Outcome.FAILURE,
        "too_many_failures",
        "root",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Disconnecting invalid user test 203.0.113.7 port 22: "
        "Too many authentication failures [preauth]",
        "ssh.auth.too_many_failures",
        Outcome.FAILURE,
        "unknown_user",
        "test",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
    (
        "sshd[1]: Disconnected from user alice 192.0.2.10 port 50500",
        "ssh.disconnect",
        Outcome.UNKNOWN,
        None,
        "alice",
        "192.0.2.10",
        EventCategory.NETWORK,
    ),
    (
        "sshd[1]: Disconnected from authenticating user root 203.0.113.7 port 22 [preauth]",
        "ssh.disconnect",
        Outcome.UNKNOWN,
        None,
        "root",
        "203.0.113.7",
        EventCategory.NETWORK,
    ),
    (
        "sshd[1]: Disconnected from invalid user admin 203.0.113.7 port 22 [preauth]",
        "ssh.disconnect",
        Outcome.UNKNOWN,
        None,
        "admin",
        "203.0.113.7",
        EventCategory.NETWORK,
    ),
    (
        "sshd[1]: Disconnected from 203.0.113.7 port 22 [preauth]",
        "ssh.disconnect",
        Outcome.UNKNOWN,
        None,
        None,
        "203.0.113.7",
        EventCategory.NETWORK,
    ),
    (
        "sshd[1]: Received disconnect from 203.0.113.7 port 22:11: Bye Bye [preauth]",
        "ssh.disconnect",
        Outcome.UNKNOWN,
        None,
        None,
        "203.0.113.7",
        EventCategory.NETWORK,
    ),
    (
        "sshd[1]: Connection closed by 198.51.100.23 port 40122 [preauth]",
        "ssh.disconnect",
        Outcome.UNKNOWN,
        None,
        None,
        "198.51.100.23",
        EventCategory.NETWORK,
    ),
    (
        "sshd[1]: Connection closed by authenticating user root 203.0.113.7 port 22 [preauth]",
        "ssh.disconnect",
        Outcome.UNKNOWN,
        None,
        "root",
        "203.0.113.7",
        EventCategory.NETWORK,
    ),
    (
        "sshd[1]: Connection closed by invalid user admin 203.0.113.7 port 22 [preauth]",
        "ssh.disconnect",
        Outcome.UNKNOWN,
        None,
        "admin",
        "203.0.113.7",
        EventCategory.NETWORK,
    ),
    (
        "sshd-session[1]: Failed password for root from 203.0.113.7 port 22 ssh2",
        "ssh.login.failure",
        Outcome.FAILURE,
        "bad_password",
        "root",
        "203.0.113.7",
        EventCategory.AUTHENTICATION,
    ),
]


@pytest.mark.parametrize(
    ("message", "action", "outcome", "reason", "user", "ip", "category"), SSHD_CASES
)
def test_sshd_lines(
    message: str,
    action: str,
    outcome: Outcome,
    reason: str | None,
    user: str | None,
    ip: str | None,
    category: EventCategory,
) -> None:
    event = one(f"{HDR} {message}")
    assert event.log_source == "sshd"
    assert event.event.action == action
    assert event.event.outcome is outcome
    assert event.event.reason == reason
    assert event.event.category is category
    assert event.user.name == user
    assert event.source.ip == (ip_address(ip) if ip else None)
    assert event.host == "web01"
    assert event.extra["pid"] == 1


class TestSshdDetails:
    def test_port_and_method_in_extra(self) -> None:
        event = one(f"{HDR} sshd[7]: Accepted password for alice from 192.0.2.10 port 50500 ssh2")
        assert event.extra == {"pid": 7, "source_port": 50500, "auth_method": "password"}

    def test_username_cannot_spoof_source_ip(self) -> None:
        event = one(
            f"{HDR} sshd[1]: Failed password for invalid user x from 192.0.2.1 port 1 ssh2 "
            "from 203.0.113.9 port 4242 ssh2"
        )
        assert event.source.ip == ip_address("203.0.113.9")
        assert event.user.name == "x from 192.0.2.1 port 1 ssh2"
        assert event.extra["source_port"] == 4242

    def test_username_with_spaces(self) -> None:
        event = one(f"{HDR} sshd[1]: Invalid user John Smith from 203.0.113.7 port 1")
        assert event.user.name == "John Smith"

    def test_ipv4_mapped_ipv6_normalised(self) -> None:
        event = one(f"{HDR} sshd[1]: Failed password for root from ::ffff:203.0.113.7 port 2 ssh2")
        assert event.source.ip == ip_address("203.0.113.7")

    def test_hostname_instead_of_address(self) -> None:
        event = one(f"{HDR} sshd[1]: Failed password for root from scanner.example port 2 ssh2")
        assert event.source.ip is None
        assert event.extra["source_host"] == "scanner.example"

    def test_unrelated_sshd_message_skipped(self) -> None:
        events, stats = parse(f"{HDR} sshd[1]: Server listening on 0.0.0.0 port 22.")
        assert events == []
        assert stats.skipped == 1

    def test_header_without_pid(self) -> None:
        event = one(f"{HDR} sshd: Failed password for root from 203.0.113.7 port 22 ssh2")
        assert "pid" not in event.extra


class TestPam:
    def test_auth_failure(self) -> None:
        event = one(
            f"{HDR} sshd[1]: pam_unix(sshd:auth): authentication failure; logname= uid=0 "
            "euid=0 tty=ssh ruser= rhost=203.0.113.7  user=root"
        )
        assert event.event.action == "pam.auth.failure"
        assert event.event.outcome is Outcome.FAILURE
        assert event.user.name == "root"
        assert event.source.ip == ip_address("203.0.113.7")
        assert event.extra["pam_service"] == "sshd"

    def test_auth_failure_without_user_or_host(self) -> None:
        event = one(
            f"{HDR} sudo: pam_unix(sudo:auth): authentication failure; logname=bob uid=1000 "
            "euid=0 tty=/dev/pts/1 ruser=bob rhost="
        )
        assert event.user.name is None
        assert event.source.ip is None
        assert event.extra["remote_user"] == "bob"

    @pytest.mark.parametrize(
        ("message", "action", "user", "by"),
        [
            (
                "sshd[1]: pam_unix(sshd:session): session opened for user alice(uid=1000) "
                "by (uid=0)",
                "session.opened",
                "alice",
                None,
            ),
            (
                "sudo: pam_unix(sudo:session): session opened for user root(uid=0) "
                "by alice(uid=1000)",
                "session.opened",
                "root",
                "alice",
            ),
            (
                "sshd[1]: pam_unix(sshd:session): session closed for user alice",
                "session.closed",
                "alice",
                None,
            ),
        ],
    )
    def test_sessions(self, message: str, action: str, user: str, by: str | None) -> None:
        event = one(f"{HDR} {message}")
        assert event.event.action == action
        assert event.event.category is EventCategory.SESSION
        assert event.user.name == user
        assert event.extra.get("by_user") == by

    def test_other_pam_message_skipped(self) -> None:
        events, stats = parse(f"{HDR} sshd[1]: pam_unix(sshd:account): account expired")
        assert (events, stats.skipped) == ([], 1)


class TestSudo:
    def test_command(self) -> None:
        event = one(
            f"{HDR} sudo:    alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; "
            "COMMAND=/usr/bin/apt update"
        )
        assert event.log_source == "sudo"
        assert event.event.action == "sudo.command"
        assert event.event.category is EventCategory.ADMIN
        assert event.event.outcome is Outcome.SUCCESS
        assert event.user.name == "alice"
        assert event.extra["target_user"] == "root"
        assert event.extra["command"] == "/usr/bin/apt update"

    def test_command_with_semicolons_in_arguments(self) -> None:
        event = one(
            f"{HDR} sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh -c echo a;b"
        )
        assert event.extra["command"] == "/bin/sh -c echo a;b"

    def test_newer_format_with_env(self) -> None:
        event = one(
            f"{HDR} sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; ENV=A=1 ; COMMAND=/usr/bin/id"
        )
        assert event.extra["command"] == "/usr/bin/id"

    def test_incorrect_password(self) -> None:
        event = one(
            f"{HDR} sudo: bob : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/home/bob ; "
            "USER=root ; COMMAND=/bin/bash"
        )
        assert event.event.action == "sudo.auth.failure"
        assert event.event.reason == "bad_password"
        assert event.extra["attempts"] == 3

    def test_not_in_sudoers(self) -> None:
        event = one(
            f"{HDR} sudo: mallory : user NOT in sudoers ; TTY=pts/2 ; PWD=/tmp ; USER=root ; "
            "COMMAND=/bin/cat /etc/shadow"
        )
        assert event.event.action == "sudo.denied"
        assert event.event.category is EventCategory.AUTHORIZATION
        assert event.event.outcome is Outcome.FAILURE

    def test_other_note(self) -> None:
        event = one(
            f"{HDR} sudo: alice : a password is required ; TTY=pts/0 ; PWD=/ ; USER=root ; "
            "COMMAND=/bin/ls"
        )
        assert event.event.outcome is Outcome.UNKNOWN
        assert event.extra["note"] == "a password is required"

    def test_sudo_line_without_command_skipped(self) -> None:
        events, stats = parse(f"{HDR} sudo: alice : TTY=pts/0 ; PWD=/")
        assert (events, stats.skipped) == ([], 1)


class TestTimestamps:
    def test_rfc3164_uses_year_and_timezone(self) -> None:
        event = one(
            "Oct 24 19:50:02 web01 sshd[1]: Invalid user a from 203.0.113.7 port 1",
            timezone="Asia/Dhaka",
        )
        assert event.timestamp == datetime(2026, 10, 24, 13, 50, 2, tzinfo=UTC)

    def test_single_digit_day(self) -> None:
        event = one("Jan  5 01:02:03 h sshd[1]: Invalid user a from 203.0.113.7 port 1")
        assert event.timestamp == datetime(2026, 1, 5, 1, 2, 3, tzinfo=UTC)

    def test_iso_with_offset_and_nanoseconds(self) -> None:
        event = one(
            "2026-10-24T19:50:02.123456789+06:00 h sshd[1]: Invalid user a from 203.0.113.7 port 1"
        )
        assert event.timestamp == datetime(2026, 10, 24, 13, 50, 2, 123456, tzinfo=UTC)

    def test_iso_with_z(self) -> None:
        event = one("2026-10-24T13:50:02Z h sshd[1]: Invalid user a from 203.0.113.7 port 1")
        assert event.timestamp == datetime(2026, 10, 24, 13, 50, 2, tzinfo=UTC)

    def test_iso_without_offset_uses_timezone(self) -> None:
        event = one(
            "2026-10-24T19:50:02 h sshd[1]: Invalid user a from 203.0.113.7 port 1",
            timezone=timezone(timedelta(hours=6)),
        )
        assert event.timestamp == datetime(2026, 10, 24, 13, 50, 2, tzinfo=UTC)

    def test_new_year_rollover(self) -> None:
        events, _ = parse(
            "Dec 31 23:59:58 h sshd[1]: Invalid user a from 203.0.113.7 port 1",
            "Jan  1 00:00:02 h sshd[1]: Invalid user a from 203.0.113.7 port 1",
            "Jan  1 00:00:03 h sshd[1]: Invalid user a from 203.0.113.7 port 1",
            year=2025,
        )
        assert [e.timestamp.year for e in events] == [2025, 2026, 2026]

    def test_late_line_from_previous_year(self) -> None:
        events, _ = parse(
            "Dec 31 23:59:58 h sshd[1]: Invalid user a from 203.0.113.7 port 1",
            "Jan  1 00:00:02 h sshd[1]: Invalid user a from 203.0.113.7 port 1",
            "Dec 31 23:59:59 h sshd[1]: Invalid user a from 203.0.113.7 port 1",
            "Jan  1 00:00:04 h sshd[1]: Invalid user a from 203.0.113.7 port 1",
            year=2025,
        )
        assert [e.timestamp.year for e in events] == [2025, 2026, 2025, 2026]

    def test_year_inferred_from_reference_time(self) -> None:
        reference = datetime(2026, 1, 3, 12, 0, tzinfo=UTC)
        parser = AuthLogParser(reference_time=reference)
        lines = iter_text_lines(
            [
                "Dec 30 10:00:00 h sshd[1]: Invalid user a from 203.0.113.7 port 1",
                "Jan  2 10:00:00 h sshd[1]: Invalid user a from 203.0.113.7 port 1",
            ]
        )
        assert [e.timestamp.year for e in parser.parse(lines)] == [2025, 2026]

    def test_reference_time_same_year(self) -> None:
        parser = AuthLogParser(reference_time=datetime(2026, 10, 25, tzinfo=UTC))
        lines = iter_text_lines(["Oct 24 10:00:00 h sshd[1]: Invalid user a from 192.0.2.1 port 1"])
        assert next(parser.parse(lines)).timestamp.year == 2026

    def test_year_from_file_mtime(self, tmp_path: Path) -> None:
        log = tmp_path / "auth.log"
        log.write_bytes(b"Dec 30 10:00:00 h sshd[1]: Invalid user a from 203.0.113.7 port 1\n")
        mtime = datetime(2026, 1, 3, tzinfo=UTC).timestamp()
        os.utime(log, (mtime, mtime))
        (event,) = AuthLogParser().parse_file(log)
        assert event.timestamp.year == 2025

    def test_leap_day(self) -> None:
        event = one("Feb 29 12:00:00 h sshd[1]: Invalid user a from 192.0.2.1 port 1", year=2028)
        assert event.timestamp.day == 29

    def test_invalid_date_is_an_error(self) -> None:
        events, stats = parse("Feb 29 12:00:00 h sshd[1]: Invalid user a from 192.0.2.1 port 1")
        assert events == []
        assert stats.errors == 1
        assert "invalid date" in stats.error_examples[0].reason

    def test_invalid_timezone_rejected(self) -> None:
        with pytest.raises(ValueError, match="unknown timezone"):
            AuthLogParser(timezone="Mars/Olympus_Mons")

    def test_year_out_of_range_rejected(self) -> None:
        with pytest.raises(ValueError, match="year"):
            AuthLogParser(year=1)

    def test_state_resets_between_inputs(self) -> None:
        parser = AuthLogParser(year=2025)
        dec = ["Dec 31 23:59:58 h sshd[1]: Invalid user a from 192.0.2.1 port 1"]
        jan = ["Jan  1 00:00:02 h sshd[1]: Invalid user a from 192.0.2.1 port 1"]
        list(parser.parse(iter_text_lines(dec)))
        assert next(parser.parse(iter_text_lines(jan))).timestamp.year == 2025


class TestMalformedInput:
    @pytest.mark.parametrize(
        ("line", "reason"),
        [
            ("garbage without a timestamp", "no syslog timestamp"),
            ("Foo 24 13:50:02 h sshd[1]: x", "unknown month"),
            ("Oct 24 13:50:02 lonelyhost", "no syslog host/program tag"),
            ("2026-13-40T99:99:99Z h sshd[1]: x", "invalid timestamp"),
            ("Oct 24 25:61:61 h sshd[1]: x", "invalid date"),
        ],
    )
    def test_errors_are_counted_not_raised(self, line: str, reason: str) -> None:
        events, stats = parse(line)
        assert events == []
        assert stats.errors == 1
        assert reason in stats.error_examples[0].reason

    def test_other_programs_are_skipped(self) -> None:
        events, stats = parse(f"{HDR} systemd-logind[612]: New session 42 of user alice.")
        assert (events, stats.skipped, stats.errors) == ([], 1, 0)

    def test_crlf_ansi_and_control_characters(self) -> None:
        data = (
            f"{HDR} sshd[1]: Invalid user \x1b[31mev\x00il\x1b[0m from 203.0.113.7 port 1\r\n"
        ).encode()
        (event,) = AuthLogParser(year=2026).parse(read_lines(io.BytesIO(data)))
        assert event.user.name == "evil"
        assert "\r" not in event.raw
        assert "\x1b" not in event.raw

    def test_invalid_utf8_username(self) -> None:
        data = f"{HDR} sshd[1]: Invalid user ".encode() + b"\xff\xfe" + b" from 192.0.2.1 port 1\n"
        stats = ParseStats()
        (event,) = AuthLogParser(year=2026).parse(read_lines(io.BytesIO(data)), stats=stats)
        assert event.user.name == "��"
        assert stats.decode_errors == 1

    def test_huge_line_is_an_error(self) -> None:
        events, stats = parse(f"{HDR} sshd[1]: Invalid user {'a' * 20000} from 192.0.2.1 port 1")
        assert (events, stats.errors) == ([], 1)

    def test_long_username_truncated_by_schema(self) -> None:
        event = one(f"{HDR} sshd[1]: Invalid user {'a' * 5000} from 192.0.2.1 port 1")
        assert event.user.name is not None
        assert len(event.user.name) == 256

    @settings(max_examples=300)
    @given(st.text(max_size=400))
    def test_arbitrary_text_never_raises(self, text: str) -> None:
        events, stats = parse(*text.split("\n"))
        assert stats.lines == stats.events + stats.skipped + stats.blank + stats.errors
        assert len(events) == stats.events

    @settings(max_examples=300)
    @given(
        st.sampled_from(["Oct 24 13:50:02 h sshd[1]: ", "2026-10-24T13:50:02Z h sudo: "]),
        st.text(max_size=300),
    )
    def test_arbitrary_messages_never_raise(self, header: str, message: str) -> None:
        line = header + message.replace("\n", " ").replace("\r", " ")
        _, stats = parse(line)
        assert stats.lines == 1


class TestIdsAndFiles:
    def test_duplicate_lines_get_distinct_ids(self) -> None:
        line = f"{HDR} sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2"
        events, _ = parse(line, line)
        assert events[0].id != events[1].id

    def test_ids_are_deterministic(self) -> None:
        line = f"{HDR} sshd[1]: Failed password for root from 203.0.113.7 port 22 ssh2"
        assert parse(line)[0][0].id == parse(line)[0][0].id

    def test_sample_file(self) -> None:
        stats = ParseStats()
        events = list(AuthLogParser(year=2026).parse_file(SAMPLES / "auth.log", stats=stats))
        assert stats.errors == 0
        assert stats.events == len(events) >= 25
        actions = {e.event.action for e in events}
        assert {"ssh.login.failure", "ssh.login.success", "sudo.command", "sudo.denied"} <= actions

    def test_sample_iso_file(self) -> None:
        stats = ParseStats()
        events = list(AuthLogParser().parse_file(SAMPLES / "auth-iso.log", stats=stats))
        assert (stats.errors, len(events)) == (0, 4)

    def test_sample_new_year_file(self) -> None:
        events = list(AuthLogParser(year=2025).parse_file(SAMPLES / "auth-newyear.log"))
        assert [e.timestamp.year for e in events] == [2025, 2025, 2026, 2026]

    def test_crlf_file(self, tmp_path: Path) -> None:
        crlf = (SAMPLES / "auth.log").read_bytes().replace(b"\n", b"\r\n")
        path = tmp_path / "auth-crlf.log"
        path.write_bytes(crlf)
        lf_events = list(AuthLogParser(year=2026).parse_file(SAMPLES / "auth.log"))
        crlf_events = list(AuthLogParser(year=2026).parse_file(path))
        assert [e.raw for e in crlf_events] == [e.raw for e in lf_events]

    def test_large_input_streams_with_bounded_memory(self) -> None:
        line = (
            b"Oct 24 13:50:02 web01 sshd[2120]: Failed password for invalid user admin "
            b"from 203.0.113.7 port 51234 ssh2\n"
        )

        class Repeat(io.RawIOBase):
            def __init__(self, count: int) -> None:
                self.remaining = count

            def readable(self) -> bool:
                return True

            def readinto(self, buffer: bytearray | memoryview) -> int:  # type: ignore[override]
                if self.remaining == 0:
                    return 0
                self.remaining -= 1
                buffer[: len(line)] = line
                return len(line)

        def consume(events: Iterator[Event]) -> int:
            return sum(1 for _ in events)

        def peak_memory(count: int) -> int:
            stream = io.BufferedReader(Repeat(count), buffer_size=len(line))
            tracemalloc.start()
            try:
                assert consume(AuthLogParser(year=2026).parse(read_lines(stream))) == count
                return tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()

        # Ten times the input must not need noticeably more memory: nothing is accumulated.
        # (tracemalloc is slow, so the full 100k-line run is below, without it.)
        small, large = peak_memory(1_000), peak_memory(10_000)
        assert large < small + 256 * 1024

        stream = io.BufferedReader(Repeat(100_000), buffer_size=len(line))
        assert consume(AuthLogParser(year=2026).parse(read_lines(stream))) == 100_000
