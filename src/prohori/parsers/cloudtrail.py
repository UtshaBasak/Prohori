# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Parser for AWS CloudTrail records, one record per line.

Each line is recognised on its own, so a file may mix the layouts:

* a **CloudTrail record** (``eventVersion``, ``eventTime``, ``eventSource``, ``eventName``), as
  in the trail files CloudTrail writes to S3 or in CloudWatch Logs;
* an **Event history** item from ``aws cloudtrail lookup-events`` (the record is the JSON text
  in ``CloudTrailEvent``);
* an **EventBridge** event (``detail-type`` "... via CloudTrail", the record in ``detail``).

The trail files themselves (``{"Records": [...]}``, usually gzip-compressed, often one very long
line) and ``lookup-events`` output (``{"Events": [...]}``) are split into one record per line
before they reach the parser, by :mod:`prohori.parsers.cloudtrail_file`.

=========================  =================================================================
CloudTrail field           Event field
=========================  =================================================================
``eventTime``              ``timestamp``
``eventSource``            ``cloud.service``, and the service in ``event.action``
``eventName``              ``event.action`` (``aws.<service>.<name in snake case>``), and
                           ``extra.event_name`` as written
``errorCode``              ``event.outcome`` failure, ``event.reason`` (``access_denied`` for
                           every denial code), ``extra.error_code`` as written
``userIdentity``           ``user.name``, ``user.id`` (the ARN), ``extra.identity_type``, ...
``sourceIPAddress``        ``source.ip``; a service name (``ec2.amazonaws.com``,
                           ``AWS Internal``) goes to ``extra.source_service`` instead
``userAgent``              ``user_agent``
``awsRegion``              ``cloud.region``
``recipientAccountId``     ``cloud.account_id``
``requestID``              ``request_id``
=========================  =================================================================

Values the rules compare across fields are worked out here, because rules match one field at a
time: ``extra.for_other_user`` (an IAM call about a user other than the caller) and
``extra.world_ports`` (the ports a security-group change opens to ``0.0.0.0/0`` or ``::/0``).
"""

import json
import re
from typing import Any

from prohori.parsers.base import MAX_LINE_LENGTH, LineParser, ParseError
from prohori.parsers.network import parse_iso
from prohori.parsers.registry import register
from prohori.parsers.util import load_json_object, normalise_ip
from prohori.schema import Event
from prohori.schema.ids import event_id

#: Error codes of a request the caller was not allowed to make; all become ``access_denied``.
DENIED_CODES = frozenset(
    {
        "AccessDenied",
        "AccessDeniedException",
        "UnauthorizedOperation",
        "Client.UnauthorizedOperation",
        "AuthorizationError",
        "AuthorizationErrorException",
    }
)
#: The user name CloudTrail writes for a failed console sign-in with a name that does not exist.
HIDDEN_USER = "HIDDEN_DUE_TO_SECURITY_REASONS"
#: Addresses that open a rule to every address.
WORLD_CIDRS = frozenset({"0.0.0.0/0", "::/0"})
#: Most security-group permissions, and address ranges per permission, read from one request.
MAX_PERMISSIONS = 1000
MAX_RANGES = 1000

#: IAM operations that change identities, credentials or permissions (category ``account``).
_IAM_CHANGES = (
    "Add",
    "Attach",
    "Change",
    "Create",
    "Deactivate",
    "Delete",
    "Detach",
    "Enable",
    "Put",
    "Remove",
    "Reset",
    "Resync",
    "Set",
    "Tag",
    "Untag",
    "Update",
    "Upload",
)
#: STS operations that hand out credentials (category ``authentication``).
_STS_SIGNINS = frozenset(
    {
        "AssumeRole",
        "AssumeRoleWithSAML",
        "AssumeRoleWithWebIdentity",
        "AssumeRoot",
        "GetFederationToken",
        "GetSessionToken",
    }
)
_CAMEL_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_NOT_WORD_RE = re.compile(r"[^a-z0-9]+")
_DETAIL_TYPE_RE = re.compile(r" via CloudTrail$")


def snake_case(name: str) -> str:
    """``DeactivateMFADevice`` -> ``deactivate_mfa_device``; anything else becomes ``_``."""
    words = _CAMEL_RE.sub("_", name).lower()
    return _NOT_WORD_RE.sub("_", words).strip("_")


def service_name(event_source: str) -> str:
    """``iam.amazonaws.com`` -> ``iam``, ``access-analyzer.amazonaws.com`` -> ``access_analyzer``.

    Anything outside ``[a-z0-9]`` becomes ``_``.
    """
    head = event_source.lower().removesuffix(".amazonaws.com").split(".")[0]
    return _NOT_WORD_RE.sub("_", head).strip("_")


def _text(value: object) -> str | None:
    if isinstance(value, str):
        return value or None
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int | float):
        return str(value)
    return None


def _flag(value: object) -> bool | None:
    """CloudTrail's ``"true"``/``"false"`` and ``"Yes"``/``"No"`` as a boolean."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "yes"}:
            return True
        if lowered in {"false", "no"}:
            return False
    return None


def _dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _items(value: object, limit: int) -> list[dict[str, Any]]:
    """A CloudTrail list: ``{"items": [...]}`` or a plain list, objects only, at most ``limit``."""
    if isinstance(value, dict):
        value = value.get("items")
    if not isinstance(value, list):
        return []
    return [item for item in value[:limit] if isinstance(item, dict)]


def _port(value: object) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip()[:6])
    return None


def _ports(permission: dict[str, Any]) -> str:
    """The ports of one permission: ``22``, ``8000-8080``, ``all`` or the protocol (``icmp``)."""
    protocol = str(permission.get("ipProtocol", "")).lower()
    if protocol in {"-1", "all"}:
        return "all"
    low, high = _port(permission.get("fromPort")), _port(permission.get("toPort"))
    if low is None or low < 0:
        return protocol or "all"
    if high is None or high == low:
        return str(low)
    return f"{low}-{high}"


def _permissions(request: dict[str, Any]) -> list[dict[str, Any]]:
    permissions = _items(request.get("ipPermissions"), MAX_PERMISSIONS)
    if "cidrIp" in request or "cidrIpv6" in request:  # the older single-rule form
        permissions.append(request)
    return permissions


def _cidrs(permission: dict[str, Any]) -> list[str]:
    cidrs = [
        str(r["cidrIp"]) for r in _items(permission.get("ipRanges"), MAX_RANGES) if "cidrIp" in r
    ]
    cidrs += [
        str(r["cidrIpv6"])
        for r in _items(permission.get("ipv6Ranges"), MAX_RANGES)
        if "cidrIpv6" in r
    ]
    for key in ("cidrIp", "cidrIpv6"):
        if isinstance(permission.get(key), str):
            cidrs.append(permission[key])
    return [c.strip() for c in cidrs]


def ingress(request: dict[str, Any]) -> tuple[str | None, str | None]:
    """The address ranges a security-group change allows, and the ports it opens to everyone.

    Both are comma-separated and without repeats; ranges open to everyone come first.
    """
    cidrs: list[str] = []
    world: list[str] = []
    for permission in _permissions(request):
        ranges = _cidrs(permission)
        cidrs.extend(ranges)
        if WORLD_CIDRS & set(ranges):
            world.append(_ports(permission))
    unique = list(dict.fromkeys(sorted(cidrs, key=lambda c: c not in WORLD_CIDRS)))
    return (",".join(unique) or None, ",".join(dict.fromkeys(world)) or None)


def _category(service: str, name: str) -> str:
    if service == "signin":
        return "authentication"
    if service == "sts":
        return "authentication" if name in _STS_SIGNINS else "cloud"
    if service == "iam" and name.startswith(_IAM_CHANGES):
        return "account"
    return "cloud"


def _identity(identity: dict[str, Any]) -> tuple[str | None, str | None, dict[str, object]]:
    """``user.name``, ``user.id`` and extra fields from ``userIdentity``."""
    kind = _text(identity.get("type"))
    arn = _text(identity.get("arn"))
    name = _text(identity.get("userName"))
    extra: dict[str, object] = {"identity_type": kind}
    if name == HIDDEN_USER:
        name = None
        extra["user_hidden"] = True
    if kind == "Root":
        name = "root"
    elif kind in {"AssumedRole", "FederatedUser"} and arn and "/" in arn:
        name = arn.split("/", 1)[1]  # role/session or the federated user's name
    elif kind in {"AWSService", "AWSAccount"}:
        name = None
    elif kind == "IdentityCenterUser" and name is None:
        name = _text(_dict(identity.get("onBehalfOf")).get("userId"))
    key = _text(identity.get("accessKeyId"))
    if key:
        extra["access_key_id"] = key
        extra["access_key_type"] = (
            "long_term"
            if key.startswith("AKIA")
            else "temporary"
            if key.startswith("ASIA")
            else None
        )
    extra["invoked_by"] = _text(identity.get("invokedBy"))
    context = _dict(identity.get("sessionContext"))
    extra["mfa_authenticated"] = _flag(_dict(context.get("attributes")).get("mfaAuthenticated"))
    issuer = _dict(context.get("sessionIssuer"))
    extra["session_issuer"] = _text(issuer.get("userName"))
    return name, arn or _text(identity.get("principalId")), extra


def unwrap(record: dict[str, Any]) -> dict[str, Any] | None:
    """The CloudTrail record inside ``record`` (itself, an Event history item, an EventBridge
    event), or ``None`` for one that is not relevant (an Insights event, an EventBridge event
    from another service)."""
    if isinstance(record.get("CloudTrailEvent"), str):
        record = load_json_object(record["CloudTrailEvent"])
    elif isinstance(record.get("detail-type"), str) and isinstance(record.get("detail"), dict):
        if not _DETAIL_TYPE_RE.search(record["detail-type"]):
            return None  # another service's event on the same bus: not relevant
        record = record["detail"]
    elif isinstance(record.get("cloudtrail_error"), str):  # from prohori.parsers.cloudtrail_file
        raise ParseError(record["cloudtrail_error"][:200])
    elif isinstance(record.get("Records"), list) or isinstance(record.get("Events"), list):
        raise ParseError("a whole CloudTrail file on one line; read the file itself")
    if record.get("eventType") == "AwsCloudTrailInsight":
        return None
    for key in ("eventTime", "eventSource", "eventName"):
        if not isinstance(record.get(key), str) or not record[key]:
            raise ParseError(f"not a CloudTrail record: missing {key}")
    return record


@register
class CloudTrailParser(LineParser):
    """Parse AWS CloudTrail records (one per line) into events.

    Args:
        log_source: Value for ``log_source``.
    """

    name = "cloudtrail"

    def __init__(self, *, log_source: str = "aws-cloudtrail") -> None:
        self.log_source = log_source

    def parse_line(self, line: str, number: int, source: str) -> Event | None:
        record = unwrap(load_json_object(line))
        if record is None:
            return None
        return self._event(record, line, f"{source}:{number}")

    def _event(self, record: dict[str, Any], raw: str, position: str) -> Event:
        timestamp = parse_iso(record["eventTime"], "eventTime")
        event_source, event_name = record["eventSource"], record["eventName"]
        service = service_name(event_source)
        action = snake_case(event_name)
        if not service or not action:
            raise ParseError(f"invalid eventSource or eventName {event_name[:40]!r}")
        name, user_id, extra = _identity(_dict(record.get("userIdentity")))
        request = _dict(record.get("requestParameters"))
        response = _dict(record.get("responseElements"))
        additional = _dict(record.get("additionalEventData"))

        error_code = _text(record.get("errorCode"))
        error_message = _text(record.get("errorMessage"))
        status = (
            _text(response.get(event_name)) if event_name in {"ConsoleLogin", "CheckMfa"} else None
        )
        if error_code or status == "Failure":
            outcome = "failure"
        elif status not in {None, "Success"}:
            outcome = "unknown"
        else:
            outcome = "success"
        reason = "access_denied" if error_code in DENIED_CODES else error_code or error_message

        address = _text(record.get("sourceIPAddress"))
        ip = normalise_ip(address)
        target = _text(request.get("userName")) if service == "iam" else None
        extra.update(
            {
                "event_name": event_name,
                "event_type": _text(record.get("eventType")),
                "event_id": _text(record.get("eventID")),
                "read_only": _flag(record.get("readOnly")),
                "error_code": error_code,
                "error_message": error_message,
                "source_service": address if ip is None else None,
                "mfa_used": _flag(additional.get("MFAUsed")),
                "target_user": target,
                "for_other_user": _for_other_user(target, extra.get("identity_type"), name),
                "trimmed": True if record.get("prohori_trimmed") is True else None,
            }
        )
        if service == "cloudtrail":
            extra["trail"] = _text(request.get("name"))
        if service == "ec2" and "SecurityGroup" in event_name:
            extra["security_group"] = _text(request.get("groupId")) or _text(
                request.get("groupName")
            )
            extra["ingress_cidrs"], extra["world_ports"] = ingress(request)
        account = _text(record.get("recipientAccountId")) or _text(
            _dict(record.get("userIdentity")).get("accountId")
        )
        return Event.model_validate(
            {
                "id": event_id(self.log_source, timestamp, raw, position),
                "timestamp": timestamp,
                "log_source": self.log_source,
                "event": {
                    "action": f"aws.{service}.{action}"[:128].rstrip("._"),
                    "category": _category(service, event_name),
                    "outcome": outcome,
                    "reason": reason,
                },
                "source": {"ip": ip},
                "user": {"name": name, "id": user_id},
                "user_agent": _text(record.get("userAgent")),
                "request_id": _text(record.get("requestID")),
                "cloud": {
                    "provider": "aws",
                    "account_id": account,
                    "region": _text(record.get("awsRegion")),
                    "service": event_source,
                },
                "raw": raw,
                "extra": {key: value for key, value in extra.items() if value is not None},
            }
        )


def _for_other_user(target: str | None, kind: object, caller: str | None) -> bool | None:
    """Whether an IAM call names a user other than the caller (``None`` when it names none)."""
    if target is None:
        return None
    return not (kind == "IAMUser" and caller == target)


# ------------------------------------------------------------------ oversized records

#: Parts of a record dropped first when it is longer than a line may be.
_BULKY = ("responseElements", "additionalEventData", "serviceEventDetails", "resources")
#: Values of the bulky parts that the mapping reads, kept when the rest is dropped.
_KEEP = {"responseElements": ("ConsoleLogin", "CheckMfa"), "additionalEventData": ("MFAUsed",)}
#: Request parameters the mapping reads.
_REQUEST_KEYS = ("userName", "name", "groupId", "groupName", "cidrIp", "cidrIpv6", "ipProtocol")
#: Security-group permissions (and address ranges in each) kept when a record is shortened.
_KEPT_PERMISSIONS = 32
_KEPT_RANGES = 8
#: Longest string kept when a record is still too long after the bulky parts are dropped.
_LONGEST_TEXT = 1024


def compact(record: object) -> str:
    """One record as one line of compact JSON."""
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False)


def shrink(record: dict[str, Any], limit: int = MAX_LINE_LENGTH) -> str | None:
    """``record`` as one line of at most ``limit`` characters, or ``None`` if it cannot be.

    A record over the limit loses, in turn, its response, additional data and resource lists
    (keeping the values the mapping reads), every request parameter the mapping does not read
    (security-group permissions are kept, those open to everyone first), and the end of every
    string longer than 1,024 characters. It is marked ``"prohori_trimmed": true``.
    """
    line = compact(record)
    if len(line) <= limit:
        return line
    record = dict(record)
    record["prohori_trimmed"] = True
    for key in _BULKY:
        if key in record:
            part = _dict(record.pop(key))
            kept = {k: part[k] for k in _KEEP.get(key, ()) if isinstance(part.get(k), str)}
            if kept:
                record[key] = kept
    line = compact(record)
    if len(line) <= limit:
        return line
    request = _dict(record.get("requestParameters"))
    essential: dict[str, Any] = {k: request[k] for k in _REQUEST_KEYS if k in request}
    for key in ("fromPort", "toPort"):
        if key in request:
            essential[key] = request[key]
    permissions = [_essential_permission(p) for p in _items(request.get("ipPermissions"), 10_000)]
    if permissions:
        permissions.sort(key=lambda p: not (WORLD_CIDRS & set(_cidrs(p))))
        essential["ipPermissions"] = {"items": permissions[:_KEPT_PERMISSIONS]}
    record["requestParameters"] = essential
    line = compact(record)
    if len(line) <= limit:
        return line
    line = compact(_cut_strings(record))
    return line if len(line) <= limit else None


def _essential_permission(permission: dict[str, Any]) -> dict[str, Any]:
    kept: dict[str, Any] = {
        k: permission[k] for k in ("ipProtocol", "fromPort", "toPort") if k in permission
    }
    for key, field in (("ipRanges", "cidrIp"), ("ipv6Ranges", "cidrIpv6")):
        ranges = [r for r in _items(permission.get(key), 10_000) if field in r]
        ranges.sort(key=lambda r: r[field] not in WORLD_CIDRS)
        if ranges:
            kept[key] = {"items": [{field: r[field]} for r in ranges[:_KEPT_RANGES]]}
    return kept


def _cut_strings(value: object) -> object:
    if isinstance(value, str):
        return value[:_LONGEST_TEXT]
    if isinstance(value, dict):
        return {key: _cut_strings(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_cut_strings(item) for item in value]
    return value
