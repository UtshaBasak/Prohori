# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Tests for the ``cloudtrail`` parser, the CloudTrail file reader and :mod:`inputs`."""

import gzip
import hashlib
import io
import json
from pathlib import Path
from typing import Any

import pytest

from prohori.parsers import (
    CloudTrailParser,
    ParseStats,
    cloudtrail_file,
    detect_format,
    iter_text_lines,
    read_lines,
)
from prohori.parsers.base import MAX_LINE_LENGTH, ConvertedInput
from prohori.parsers.cloudtrail import ingress, service_name, shrink, snake_case
from prohori.parsers.detect import classify_line
from prohori.parsers.inputs import InputError, convert, open_log
from prohori.schema import Event

ROOT = Path(__file__).resolve().parents[3]
SAMPLE = ROOT / "samples" / "logs" / "aws-cloudtrail.json"
ACCOUNT = "111122223333"


def identity(name: str = "it-admin", **extra: Any) -> dict[str, Any]:
    return {
        "type": "IAMUser",
        "principalId": "AIDAEXAMPLE1",
        "arn": f"arn:aws:iam::{ACCOUNT}:user/{name}",
        "accountId": ACCOUNT,
        "accessKeyId": "ASIAEXAMPLEKEY01",
        "userName": name,
        "sessionContext": {"attributes": {"mfaAuthenticated": "true"}},
        **extra,
    }


def record(
    name: str = "ListUsers", source: str = "iam.amazonaws.com", **fields: Any
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "eventVersion": "1.11",
        "userIdentity": identity(),
        "eventTime": "2026-10-24T14:00:00Z",
        "eventSource": source,
        "eventName": name,
        "awsRegion": "ap-southeast-1",
        "sourceIPAddress": "203.0.113.50",
        "userAgent": "aws-cli/2.17.50",
        "requestParameters": None,
        "responseElements": None,
        "requestID": "req-1",
        "eventID": "evt-1",
        "readOnly": True,
        "eventType": "AwsApiCall",
        "recipientAccountId": ACCOUNT,
    }
    value.update(fields)
    return value


def parse(*records: object) -> tuple[list[Event], ParseStats]:
    stats = ParseStats()
    lines = [r if isinstance(r, str) else json.dumps(r) for r in records]
    events = list(CloudTrailParser().parse(iter_text_lines(lines), source="t", stats=stats))
    return events, stats


def one(value: object) -> Event:
    events, stats = parse(value)
    assert stats.errors == 0, stats.error_examples
    (event,) = events
    return event


# ---------------------------------------------------------------------- names


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ConsoleLogin", "console_login"),
        ("DeactivateMFADevice", "deactivate_mfa_device"),
        ("ListFunctions20150331", "list_functions20150331"),
        ("GetObjectACL", "get_object_acl"),
        ("Weird-Name.Here", "weird_name_here"),
    ],
)
def test_snake_case(name: str, expected: str) -> None:
    assert snake_case(name) == expected


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("iam.amazonaws.com", "iam"),
        ("access-analyzer.amazonaws.com", "access_analyzer"),
        ("signin.amazonaws.com", "signin"),
        ("ssm.example", "ssm"),
    ],
)
def test_service_name(source: str, expected: str) -> None:
    assert service_name(source) == expected


# ---------------------------------------------------------------------- mapping


def test_api_call_mapping() -> None:
    event = one(record())
    assert event.event.action == "aws.iam.list_users"
    assert event.event.category == "cloud"
    assert event.event.outcome == "success"
    assert event.log_source == "aws-cloudtrail"
    assert str(event.source.ip) == "203.0.113.50"
    assert event.user.name == "it-admin"
    assert event.user.id == f"arn:aws:iam::{ACCOUNT}:user/it-admin"
    assert event.user_agent == "aws-cli/2.17.50"
    assert event.request_id == "req-1"
    assert event.cloud is not None
    assert event.cloud.model_dump() == {
        "provider": "aws",
        "account_id": ACCOUNT,
        "region": "ap-southeast-1",
        "service": "iam.amazonaws.com",
    }
    assert event.extra == {
        "identity_type": "IAMUser",
        "access_key_id": "ASIAEXAMPLEKEY01",
        "access_key_type": "temporary",
        "mfa_authenticated": True,
        "event_name": "ListUsers",
        "event_type": "AwsApiCall",
        "event_id": "evt-1",
        "read_only": True,
    }
    assert json.loads(event.model_dump_json())["cloud"]["provider"] == "aws"


@pytest.mark.parametrize(
    ("source", "name", "category"),
    [
        ("signin.amazonaws.com", "ConsoleLogin", "authentication"),
        ("sts.amazonaws.com", "AssumeRole", "authentication"),
        ("sts.amazonaws.com", "GetCallerIdentity", "cloud"),
        ("iam.amazonaws.com", "CreateAccessKey", "account"),
        ("iam.amazonaws.com", "DeactivateMFADevice", "account"),
        ("iam.amazonaws.com", "GetUser", "cloud"),
        ("ec2.amazonaws.com", "AuthorizeSecurityGroupIngress", "cloud"),
        ("cloudtrail.amazonaws.com", "StopLogging", "cloud"),
    ],
)
def test_categories_never_admin(source: str, name: str, category: str) -> None:
    assert one(record(name, source)).event.category == category


def test_console_login_failure_and_success() -> None:
    failure = one(
        record(
            "ConsoleLogin",
            "signin.amazonaws.com",
            errorMessage="Failed authentication",
            responseElements={"ConsoleLogin": "Failure"},
            additionalEventData={"MFAUsed": "No"},
        )
    )
    assert (failure.event.outcome, failure.event.reason) == ("failure", "Failed authentication")
    assert failure.extra["mfa_used"] is False
    success = one(
        record(
            "ConsoleLogin",
            "signin.amazonaws.com",
            responseElements={"ConsoleLogin": "Success"},
            additionalEventData={"MFAUsed": "Yes"},
        )
    )
    assert (success.event.outcome, success.event.reason) == ("success", None)
    assert success.extra["mfa_used"] is True
    odd = one(
        record("ConsoleLogin", "signin.amazonaws.com", responseElements={"ConsoleLogin": "?"})
    )
    assert odd.event.outcome == "unknown"


def test_hidden_user_name() -> None:
    hidden = {
        "type": "IAMUser",
        "accountId": ACCOUNT,
        "accessKeyId": "",
        "userName": "HIDDEN_DUE_TO_SECURITY_REASONS",
    }
    event = one(record("ConsoleLogin", "signin.amazonaws.com", userIdentity=hidden))
    assert event.user.name is None
    assert event.user.id is None
    assert event.extra["user_hidden"] is True
    assert "access_key_id" not in event.extra


@pytest.mark.parametrize(
    ("user_identity", "name", "extra"),
    [
        (
            {
                "type": "Root",
                "principalId": ACCOUNT,
                "arn": f"arn:aws:iam::{ACCOUNT}:root",
                "accessKeyId": "AKIAEXAMPLEROOT1",
            },
            "root",
            {"access_key_type": "long_term"},
        ),
        (
            {
                "type": "AssumedRole",
                "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/ci-deploy/gh-actions-9101",
                "sessionContext": {"sessionIssuer": {"userName": "ci-deploy"}},
            },
            "ci-deploy/gh-actions-9101",
            {"session_issuer": "ci-deploy"},
        ),
        (
            {"type": "FederatedUser", "arn": f"arn:aws:sts::{ACCOUNT}:federated-user/bob"},
            "bob",
            {},
        ),
        (
            {"type": "IdentityCenterUser", "onBehalfOf": {"userId": "9067-abcd"}},
            "9067-abcd",
            {},
        ),
        (
            {"type": "AWSService", "invokedBy": "lambda.amazonaws.com"},
            None,
            {"invoked_by": "lambda.amazonaws.com"},
        ),
        ({"type": "AWSAccount", "principalId": "AIDAOTHER", "accountId": "444455556666"}, None, {}),
        (
            {"type": "IAMUser", "userName": "x", "accessKeyId": "OTHERKEY"},
            "x",
            {"access_key_id": "OTHERKEY"},
        ),
    ],
)
def test_identities(user_identity: dict[str, Any], name: str | None, extra: dict[str, Any]) -> None:
    event = one(record(userIdentity=user_identity))
    assert event.user.name == name
    assert extra.items() <= event.extra.items()


def test_service_address_goes_to_extra() -> None:
    event = one(record(sourceIPAddress="lambda.amazonaws.com"))
    assert event.source.ip is None
    assert event.source.host is None  # never a link field
    assert event.extra["source_service"] == "lambda.amazonaws.com"
    assert one(record(sourceIPAddress="AWS Internal")).extra["source_service"] == "AWS Internal"
    assert str(one(record(sourceIPAddress="::ffff:192.0.2.1")).source.ip) == "192.0.2.1"


@pytest.mark.parametrize(
    "code",
    [
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "Client.UnauthorizedOperation",
        "AuthorizationError",
    ],
)
def test_denials_have_one_reason(code: str) -> None:
    event = one(record(errorCode=code, errorMessage="not allowed"))
    assert (event.event.outcome, event.event.reason) == ("failure", "access_denied")
    assert (event.extra["error_code"], event.extra["error_message"]) == (code, "not allowed")


def test_other_errors_keep_their_code() -> None:
    event = one(record(errorCode="NoSuchEntityException"))
    assert (event.event.outcome, event.event.reason) == ("failure", "NoSuchEntityException")


@pytest.mark.parametrize(
    ("caller", "parameters", "other"),
    [
        (identity(), {"userName": "svc-reports"}, True),
        (identity(), {"userName": "it-admin"}, False),
        (identity(), None, None),
        ({"type": "Root", "arn": f"arn:aws:iam::{ACCOUNT}:root"}, {"userName": "it-admin"}, True),
        (
            {"type": "AssumedRole", "arn": f"arn:aws:sts::{ACCOUNT}:assumed-role/admin/it-admin"},
            {"userName": "it-admin"},
            True,
        ),
    ],
)
def test_for_other_user(
    caller: dict[str, Any], parameters: dict[str, Any] | None, other: bool | None
) -> None:
    event = one(record("CreateAccessKey", userIdentity=caller, requestParameters=parameters))
    assert event.extra.get("for_other_user") is other
    assert event.extra.get("target_user") == (parameters or {}).get("userName")


def test_trail_and_security_group_names() -> None:
    trail = one(
        record("StopLogging", "cloudtrail.amazonaws.com", requestParameters={"name": "main"})
    )
    assert trail.extra["trail"] == "main"
    group = one(
        record(
            "AuthorizeSecurityGroupIngress",
            "ec2.amazonaws.com",
            requestParameters={
                "groupName": "web",
                "cidrIp": "0.0.0.0/0",
                "ipProtocol": "tcp",
                "fromPort": 22,
                "toPort": 22,
            },
        )
    )
    assert (group.extra["security_group"], group.extra["world_ports"]) == ("web", "22")


def _perm(
    protocol: str,
    low: int | None,
    high: int | None,
    v4: list[str] | tuple[str, ...],
    v6: list[str] | tuple[str, ...] = (),
) -> dict[str, Any]:
    value: dict[str, Any] = {"ipProtocol": protocol}
    if low is not None:
        value["fromPort"] = low
    if high is not None:
        value["toPort"] = high
    value["ipRanges"] = {"items": [{"cidrIp": c} for c in v4]}
    value["ipv6Ranges"] = {"items": [{"cidrIpv6": c} for c in v6]}
    return value


@pytest.mark.parametrize(
    ("permissions", "cidrs", "world"),
    [
        ([_perm("tcp", 22, 22, ["0.0.0.0/0"])], "0.0.0.0/0", "22"),
        ([_perm("tcp", 8000, 8080, [], ["::/0"])], "::/0", "8000-8080"),
        ([_perm("-1", None, None, ["0.0.0.0/0"])], "0.0.0.0/0", "all"),
        ([_perm("icmp", -1, -1, ["0.0.0.0/0"])], "0.0.0.0/0", "icmp"),
        ([_perm("tcp", "443", "443", ["0.0.0.0/0"], ["::/0"])], "0.0.0.0/0,::/0", "443"),  # type: ignore[arg-type]
        ([_perm("tcp", 22, None, ["10.0.0.0/8"])], "10.0.0.0/8", None),
        (
            [
                _perm("tcp", 22, 22, ["10.0.0.0/8", "0.0.0.0/0"]),
                _perm("tcp", 22, 22, ["0.0.0.0/0"]),
            ],
            "0.0.0.0/0,10.0.0.0/8",
            "22",
        ),
        ([_perm("tcp", 22, 22, ["0.0.0.0/1", "128.0.0.0/1"])], "0.0.0.0/1,128.0.0.0/1", None),
        ([], None, None),
    ],
)
def test_ingress(permissions: list[dict[str, Any]], cidrs: str | None, world: str | None) -> None:
    assert ingress({"ipPermissions": {"items": permissions}}) == (cidrs, world)


def test_ingress_far_down_the_list_is_seen() -> None:
    permissions = [_perm("tcp", p, p, [f"10.0.{p}.0/24"]) for p in range(1, 60)]
    permissions.append(_perm("tcp", 22, 22, ["0.0.0.0/0"]))
    cidrs, world = ingress({"ipPermissions": {"items": permissions}})
    assert world == "22"
    assert cidrs is not None
    assert cidrs.startswith("0.0.0.0/0,")


# ---------------------------------------------------------------------- layouts


def test_event_history_item() -> None:
    item = {"EventId": "e", "EventName": "ListUsers", "CloudTrailEvent": json.dumps(record())}
    assert one(item).event.action == "aws.iam.list_users"


def test_eventbridge_event() -> None:
    wrapped = {
        "version": "0",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "detail": record(),
    }
    assert one(wrapped).event.action == "aws.iam.list_users"
    events, stats = parse({"detail-type": "EC2 Instance State-change Notification", "detail": {}})
    assert (events, stats.skipped, stats.errors) == ([], 1, 0)


def test_insights_events_are_skipped() -> None:
    events, stats = parse(record(eventType="AwsCloudTrailInsight"))
    assert (events, stats.skipped) == ([], 1)


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        ({"eventTime": "2026-10-24T14:00:00Z"}, "missing eventSource"),
        (record(eventTime="yesterday"), "invalid eventTime"),
        (record(eventTime="2026-10-24T14:00:00"), "eventTime has no timezone"),
        (record(eventName="---"), "invalid eventSource or eventName"),
        ({"Records": [record()]}, "a whole CloudTrail file on one line"),
        ({"cloudtrail_error": "record longer than 4 bytes"}, "record longer than 4 bytes"),
        ("[1, 2]", "not an object"),
        ("{nope", "invalid JSON"),
    ],
)
def test_errors(value: object, reason: str) -> None:
    events, stats = parse(value)
    assert events == []
    assert stats.errors == 1
    assert reason in stats.error_examples[0].reason


def test_strings_are_sanitised() -> None:
    event = one(record(userAgent="aws-cli\u001b[31m/2"))
    assert event.user_agent == "aws-cli/2"


def test_detection() -> None:
    assert classify_line(json.dumps(record())) == "cloudtrail"
    assert classify_line(json.dumps({"CloudTrailEvent": "{}"})) == "cloudtrail"
    assert (
        classify_line(json.dumps({"detail-type": "AWS Console Sign In via CloudTrail"}))
        == "cloudtrail"
    )
    assert classify_line(json.dumps({"cloudtrail_error": "x"})) == "cloudtrail"
    without = {k: v for k, v in record().items() if k not in {"eventVersion", "userIdentity"}}
    assert classify_line(json.dumps(without)) == "generic_json"
    lines = read_lines(io.BytesIO(b"\n".join(json.dumps(record()).encode() for _ in range(3))))
    assert detect_format(lines) == "cloudtrail"


# ---------------------------------------------------------------------- shrinking


def test_shrink_keeps_short_records() -> None:
    value = record()
    assert shrink(value) == json.dumps(value, separators=(",", ":"))


def test_shrink_drops_bulky_parts_but_keeps_what_the_mapping_reads() -> None:
    value = record(
        "ConsoleLogin",
        "signin.amazonaws.com",
        responseElements={"ConsoleLogin": "Failure", "padding": "x" * 30_000},
        additionalEventData={"MFAUsed": "No", "LoginTo": "x" * 100},
        resources=[{"ARN": "x" * 100}],
    )
    line = shrink(value)
    assert line is not None
    assert len(line) <= MAX_LINE_LENGTH
    kept = json.loads(line)
    assert kept["prohori_trimmed"] is True
    assert kept["responseElements"] == {"ConsoleLogin": "Failure"}
    assert kept["additionalEventData"] == {"MFAUsed": "No"}
    assert "resources" not in kept
    event = one(line)
    assert event.event.outcome == "failure"
    assert event.extra["trimmed"] is True


def test_shrink_keeps_world_open_permissions_first() -> None:
    padding = [_perm("tcp", p, p, [f"10.{p % 250}.{p // 250}.0/24"] * 3) for p in range(1, 2000)]
    request = {
        "groupId": "sg-1",
        "description": "x" * 500,
        "ipPermissions": {"items": [*padding, _perm("tcp", 3389, 3389, ["0.0.0.0/0"])]},
    }
    line = shrink(
        record("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com", requestParameters=request)
    )
    assert line is not None
    assert len(line) <= MAX_LINE_LENGTH
    event = one(line)
    assert event.extra["world_ports"] == "3389"
    assert event.extra["security_group"] == "sg-1"


def test_shrink_cuts_long_strings_then_gives_up() -> None:
    long_agent = record(userAgent="a" * 20_000)
    line = shrink(long_agent)
    assert line is not None
    assert len(json.loads(line)["userAgent"]) == 1024
    hopeless = record(userIdentity={f"k{i}": "v" * 1000 for i in range(40)})
    assert shrink(hopeless) is None


# ---------------------------------------------------------------------- reading files


def _records(count: int) -> list[dict[str, Any]]:
    return [record(eventID=f"evt-{i}") for i in range(count)]


def _read(source: object) -> list[str]:
    return [raw.text for raw in read_lines(source)]  # type: ignore[arg-type]


@pytest.mark.parametrize("compressed", [False, True])
def test_trail_file(tmp_path: Path, compressed: bool) -> None:
    data = json.dumps({"Records": _records(5)}, separators=(",", ":")).encode()
    if compressed:
        data = gzip.compress(data)
    path = tmp_path / "trail.json.gz"
    path.write_bytes(data)
    with open_log(path) as stream:
        lines = _read(stream)
        assert isinstance(stream, ConvertedInput)
        assert stream.stored_size() == len(data)
        assert stream.hexdigest() == hashlib.sha256(data).hexdigest()
    assert [json.loads(line)["eventID"] for line in lines] == [f"evt-{i}" for i in range(5)]


def test_lookup_events_output_and_chunk_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cloudtrail_file, "CHUNK", 7)  # every structure split across reads
    items = [
        {
            "EventId": str(i),
            "CloudTrailEvent": json.dumps(record(userAgent='a "quoted" [x] {y} \\')),
        }
        for i in range(3)
    ]
    data = ("﻿" + json.dumps({"Events": items, "NextToken": "abc"}, indent=4)).encode()
    lines = _read(convert(io.BytesIO(data)))
    assert len(lines) == 3
    events, stats = parse(*lines)
    assert stats.errors == 0
    assert events[0].user_agent == 'a "quoted" [x] {y} \\'


def test_json_lines_with_long_records(tmp_path: Path) -> None:
    big = record(responseElements={"padding": "x" * 40_000})
    path = tmp_path / "events.jsonl"
    path.write_text(
        "﻿" + "\n".join(json.dumps(r) for r in (record(), big, record())) + "\n\n", encoding="utf-8"
    )
    with open_log(path) as stream:
        lines = _read(stream)
    assert len(lines) == 3
    assert json.loads(lines[1])["prohori_trimmed"] is True


@pytest.mark.parametrize(
    ("data", "texts"),
    [
        (
            b'{"Records":[{"a":1}, 7, "x", [1], {"b":2}]}',
            [
                '{"a":1}',
                "error:record is a int",
                "error:record is a str",
                "error:record is a list",
                '{"b":2}',
            ],
        ),
        (b'{"Records":[{"a":1},{"b":', ['{"a":1}', "error:the file ends inside a record"]),
        (b'{"Records":[{"a": nope}, {"b":2}]}', ["error:invalid JSON record", '{"b":2}']),
        (b'{"Records":[]}', []),
        (b'{"Records":[{"a":1}]', ['{"a":1}']),
    ],
)
def test_odd_trail_files(data: bytes, texts: list[str]) -> None:
    lines = _read(convert(io.BytesIO(data)))
    assert len(lines) == len(texts)
    for line, expected in zip(lines, texts, strict=True):
        if expected.startswith("error:"):
            assert expected.removeprefix("error:") in json.loads(line)["cloudtrail_error"]
        else:
            assert json.loads(line) == json.loads(expected)


def test_json_lines_text_that_is_not_an_object() -> None:
    data = b'{"eventSource":"a","eventName":"b"}\nnot json at all\n{"c":3}\n'
    lines = _read(convert(io.BytesIO(data)))
    assert [json.loads(line).get("cloudtrail_error") for line in lines] == [
        None,
        "not a JSON object",
        None,
    ]


def test_records_over_the_limit_are_skipped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cloudtrail_file, "MAX_RECORD", 64)
    monkeypatch.setattr(cloudtrail_file, "CHUNK", 16)
    huge = {"a": "x" * 500, "b": '\\"' * 50}
    data = json.dumps({"Records": [{"a": 1}, huge, {"b": 2}]}).encode()
    lines = _read(convert(io.BytesIO(data)))
    assert json.loads(lines[1])["cloudtrail_error"] == "record longer than 64 bytes"
    assert [json.loads(lines[0]), json.loads(lines[2])] == [{"a": 1}, {"b": 2}]


def test_records_still_too_long_after_shrinking() -> None:
    hopeless = record(userIdentity={f"k{i}": "v" * 1000 for i in range(40)})
    lines = _read(convert(io.BytesIO(json.dumps({"Records": [hopeless]}).encode())))
    assert "after shortening" in json.loads(lines[0])["cloudtrail_error"]


def test_readline_returns_long_lines_in_pieces() -> None:
    stream = convert(io.BytesIO(json.dumps({"Records": [record()]}).encode()))
    first = stream.readline(10)
    rest = stream.readline()
    assert len(first) == 10
    assert json.loads(first + rest)["eventName"] == "ListUsers"
    assert stream.readline() == b""


def test_plain_files_pass_through(tmp_path: Path) -> None:
    path = tmp_path / "auth.log"
    path.write_bytes(b"line one\nline two\n")
    with open_log(path) as stream:
        assert not isinstance(stream, ConvertedInput)
        assert _read(stream) == ["line one", "line two"]


def test_gzip_text_file(tmp_path: Path) -> None:
    data = gzip.compress(b"line one\nline two\n" * 3)
    path = tmp_path / "auth.log.1"  # recognised by its content, not its name
    path.write_bytes(data)
    with open_log(path) as stream:
        assert _read(stream) == ["line one", "line two"] * 3
        assert isinstance(stream, ConvertedInput)
        assert stream.stored_size() == len(data)
        assert stream.hexdigest() == hashlib.sha256(data).hexdigest()


@pytest.mark.parametrize("cut", [10, -5])
def test_corrupt_gzip(tmp_path: Path, cut: int) -> None:
    data = gzip.compress(b"line\n" * 50_000)
    path = tmp_path / "broken.gz"
    path.write_bytes(data[:cut])
    with pytest.raises(InputError, match="gzip"), open_log(path) as stream:
        _read(stream)


def test_partial_reads_from_a_pipe() -> None:
    class Pipe(io.BytesIO):
        def read1(self, size: int | None = -1, /) -> bytes:
            return super().read(min(size, 70) if size and size > 0 else 70)

    data = json.dumps({"Records": _records(2)}).encode()
    assert len(_read(convert(Pipe(data), partial=True))) == 2
    assert _read(convert(Pipe(b"a\nb\n"), partial=True)) == ["a", "b"]


def test_sample_trail_file() -> None:
    with open_log(SAMPLE) as stream:
        events, stats = parse(*_read(stream))
    assert stats.errors == 0
    assert len(events) == 20
    assert {e.event.action for e in events} >= {
        "aws.signin.console_login",
        "aws.iam.create_access_key",
        "aws.ec2.authorize_security_group_ingress",
        "aws.cloudtrail.stop_logging",
    }
