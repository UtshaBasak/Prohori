# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Windows Security events -> common-schema events, independent of how they were exported.

Every input format (exported JSON, event XML, ``.evtx``, and later the live readers of step 46)
first builds a :class:`WindowsRecord`: the provider, the event id, the time, the computer and the
``EventData`` (or ``UserData``) values by name. :func:`to_event` then maps the record; nothing
here knows the input format.

The field names follow the event templates documented by Microsoft (Windows 10 / Server 2016 and
later; 4624 version 2). Templates only ever append fields, so older versions map too.

=====================  ====================================  ==============  =================
Event                  ``event.action``                      Category        Outcome
=====================  ====================================  ==============  =================
4624                   ``windows.logon.success``             authentication  success
4625                   ``windows.logon.failure``             authentication  failure
4634, 4647             ``windows.logoff``                    session         success
4672                   ``windows.logon.special_privileges``  authorization   success
4720                   ``windows.account.created``           account         success
4722                   ``windows.account.enabled``           account         success
4726                   ``windows.account.deleted``           account         success
4728, 4732, 4756       ``windows.group.member_added``        account         success
4740                   ``windows.account.locked_out``        authentication  failure
1102                   ``windows.log.cleared``               admin           success
=====================  ====================================  ==============  =================
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime

from prohori.parsers.base import ParseError, sanitize
from prohori.parsers.sysmon import (
    SYSMON_EVENT_IDS as SYSMON_EVENT_IDS,
)
from prohori.parsers.sysmon import (
    SYSMON_PROVIDER,
    base_name,
    sysmon_fields,
)
from prohori.parsers.util import normalise_host, normalise_ip
from prohori.schema import Event, event_id

SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"
EVENTLOG_PROVIDER = "Microsoft-Windows-Eventlog"

#: Field names in template order, for formats that give values by position only
#: (``Get-WinEvent`` objects' ``Properties``). 4728 and 4756 share 4732's template.
_GROUP_MEMBER = (
    "MemberName",
    "MemberSid",
    "TargetUserName",
    "TargetDomainName",
    "TargetSid",
    "SubjectUserSid",
    "SubjectUserName",
    "SubjectDomainName",
    "SubjectLogonId",
    "PrivilegeList",
)
_TARGET_ACCOUNT = (
    "TargetUserName",
    "TargetDomainName",
    "TargetSid",
    "SubjectUserSid",
    "SubjectUserName",
    "SubjectDomainName",
    "SubjectLogonId",
)
TEMPLATES: Mapping[int, tuple[str, ...]] = {
    4624: (
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "TargetUserSid",
        "TargetUserName",
        "TargetDomainName",
        "TargetLogonId",
        "LogonType",
        "LogonProcessName",
        "AuthenticationPackageName",
        "WorkstationName",
        "LogonGuid",
        "TransmittedServices",
        "LmPackageName",
        "KeyLength",
        "ProcessId",
        "ProcessName",
        "IpAddress",
        "IpPort",
        "ImpersonationLevel",
        "RestrictedAdminMode",
        "TargetOutboundUserName",
        "TargetOutboundDomainName",
        "VirtualAccount",
        "TargetLinkedLogonId",
        "ElevatedToken",
    ),
    4625: (
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "TargetUserSid",
        "TargetUserName",
        "TargetDomainName",
        "Status",
        "FailureReason",
        "SubStatus",
        "LogonType",
        "LogonProcessName",
        "AuthenticationPackageName",
        "WorkstationName",
        "TransmittedServices",
        "LmPackageName",
        "KeyLength",
        "ProcessId",
        "ProcessName",
        "IpAddress",
        "IpPort",
    ),
    4634: ("TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId", "LogonType"),
    4647: ("TargetUserSid", "TargetUserName", "TargetDomainName", "TargetLogonId"),
    4672: (
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "PrivilegeList",
    ),
    4720: (*_TARGET_ACCOUNT, "PrivilegeList", "SamAccountName", "DisplayName", "UserPrincipalName"),
    4722: _TARGET_ACCOUNT,
    4726: (*_TARGET_ACCOUNT, "PrivilegeList"),
    4728: _GROUP_MEMBER,
    4732: _GROUP_MEMBER,
    4756: _GROUP_MEMBER,
    4740: _TARGET_ACCOUNT,
    1102: ("SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId"),
    4688: (
        "SubjectUserSid",
        "SubjectUserName",
        "SubjectDomainName",
        "SubjectLogonId",
        "NewProcessId",
        "NewProcessName",
        "TokenElevationType",
        "ProcessId",
        "CommandLine",
        "TargetUserSid",
        "TargetUserName",
        "TargetDomainName",
        "TargetLogonId",
        "ParentProcessName",
        "MandatoryLabel",
    ),
}

LOGON_TYPES: Mapping[int, str] = {
    0: "system",
    2: "interactive",
    3: "network",
    4: "batch",
    5: "service",
    7: "unlock",
    8: "network_cleartext",
    9: "new_credentials",
    10: "remote_interactive",
    11: "cached_interactive",
    12: "cached_remote_interactive",
    13: "cached_unlock",
}

#: NTSTATUS codes of failed sign-ins (4625 ``Status`` / ``SubStatus``) -> ``event.reason``.
FAILURE_REASONS: Mapping[str, str] = {
    "0xc0000064": "unknown_user",
    "0xc000006a": "bad_password",
    "0xc0000234": "locked",
    "0xc0000072": "disabled",
    "0xc0000193": "expired",
    "0xc0000071": "password_expired",
    "0xc0000224": "password_must_change",
    "0xc000006f": "outside_hours",
    "0xc0000070": "workstation_restriction",
    "0xc000015b": "logon_type_not_granted",
    "0xc0000413": "authentication_firewall",
}

_GROUP_SCOPE = {4728: "global", 4732: "local", 4756: "universal"}
#: Values Windows writes for "nobody" or "no address".
_EMPTY = {"", "-", "%%1793", "S-1-0-0", "NULL SID"}

_ACTIONS: Mapping[int, tuple[str, str, str]] = {
    4624: ("windows.logon.success", "authentication", "success"),
    4625: ("windows.logon.failure", "authentication", "failure"),
    4634: ("windows.logoff", "session", "success"),
    4647: ("windows.logoff", "session", "success"),
    4672: ("windows.logon.special_privileges", "authorization", "success"),
    4720: ("windows.account.created", "account", "success"),
    4722: ("windows.account.enabled", "account", "success"),
    4726: ("windows.account.deleted", "account", "success"),
    # Windows audits group membership under Account Management, so these are account changes,
    # not admin actions (PRH-ADMIN-002 would otherwise flag every new account's automatic
    # addition to "Users" at night).
    4728: ("windows.group.member_added", "account", "success"),
    4732: ("windows.group.member_added", "account", "success"),
    4756: ("windows.group.member_added", "account", "success"),
    4740: ("windows.account.locked_out", "authentication", "failure"),
    1102: ("windows.log.cleared", "admin", "success"),
    4688: ("process.created", "process", "success"),
}

#: Event ids :func:`to_event` maps (others are skipped).
SUPPORTED_EVENT_IDS = frozenset(_ACTIONS)

#: Most named values kept from one record (a hostile export could list thousands).
MAX_FIELDS = 128


@dataclass(frozen=True)
class WindowsRecord:
    """One Windows event, whatever format it came in."""

    provider: str | None
    event_id: int
    timestamp: datetime
    computer: str | None = None
    record_id: int | None = None
    channel: str | None = None
    data: Mapping[str, str] = field(default_factory=dict)


def positional(event_id: int, values: list[object]) -> dict[str, str]:
    """Name values given by position (``Get-WinEvent`` ``Properties``) by the event's template."""
    names = TEMPLATES.get(event_id, ())
    return {
        name: text
        for name, value in zip(names, values, strict=False)
        if (text := scalar_text(value)) is not None
    }


def scalar_text(value: object) -> str | None:
    """A data value as text; containers are not values (``None``)."""
    if value is None or isinstance(value, dict | list):
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return sanitize(str(value))


def _value(data: Mapping[str, str], name: str) -> str | None:
    value = data.get(name)
    if value is None:
        return None
    value = value.strip()
    return None if value in _EMPTY else value


def _int(data: Mapping[str, str], name: str) -> int | None:
    value = _value(data, name)
    if value is None:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        raise ParseError(f"{name} is not a number: {value[:40]!r}") from None


def _reason(data: Mapping[str, str]) -> str:
    status = (_value(data, "Status") or "").lower()
    sub = (_value(data, "SubStatus") or "").lower()
    # 0xC000006D ("bad user name or authentication information") is refined by the SubStatus.
    for code in (sub, status) if status == "0xc000006d" or status == "" else (status, sub):
        if code in FAILURE_REASONS:
            return FAILURE_REASONS[code]
    return "auth_failed"


def is_sysmon(provider: str | None, channel: str | None) -> bool:
    """Whether a record comes from Sysmon (by provider, or by channel when there is none)."""
    if provider is not None:
        return provider == SYSMON_PROVIDER
    return channel is not None and channel.startswith(SYSMON_PROVIDER)


def is_supported(event_id: int, provider: str | None, channel: str | None) -> bool:
    """Whether :func:`to_event` maps this event id from this source."""
    if is_sysmon(provider, channel):
        return event_id in SYSMON_EVENT_IDS
    return event_id in SUPPORTED_EVENT_IDS


def to_event(
    record: WindowsRecord,
    *,
    raw: str,
    position: str,
    log_source: str = "windows-security",
    sysmon_log_source: str = "sysmon",
) -> Event | None:
    """Map one record to an event; ``None`` for an event id or provider that is not mapped."""
    if is_sysmon(record.provider, record.channel):
        return _sysmon_event(record, raw=raw, position=position, log_source=sysmon_log_source)
    mapping = _ACTIONS.get(record.event_id)
    if mapping is None:
        return None
    expected = EVENTLOG_PROVIDER if record.event_id == 1102 else SECURITY_PROVIDER
    if record.provider is not None and record.provider != expected:
        return None
    action, category, outcome = mapping
    data = dict(list(record.data.items())[:MAX_FIELDS])
    extra: dict[str, object] = {
        "event_id": record.event_id,
        "record_id": record.record_id,
        "channel": record.channel,
    }
    user_name = user_sid = ip_text = None
    reason: str | None = None
    if record.event_id in {4624, 4625, 4634, 4647}:
        user_name, user_sid = _value(data, "TargetUserName"), _value(data, "TargetUserSid")
        logon_type = _int(data, "LogonType")
        extra.update(
            {
                "target_domain": _value(data, "TargetDomainName"),
                "logon_type": logon_type,
                "logon_type_name": LOGON_TYPES.get(logon_type) if logon_type is not None else None,
                "logon_id": _value(data, "TargetLogonId"),
                "workstation": _value(data, "WorkstationName"),
                "logon_process": _value(data, "LogonProcessName"),
                "auth_package": _value(data, "AuthenticationPackageName"),
                "process_name": _value(data, "ProcessName"),
                "source_port": _int(data, "IpPort") or None,
            }
        )
        ip_text = _value(data, "IpAddress")
        if record.event_id == 4625:
            reason = _reason(data)
            extra["status"] = _value(data, "Status")
            extra["sub_status"] = _value(data, "SubStatus")
        if record.event_id == 4647:
            extra["user_initiated"] = True
    elif record.event_id in {4720, 4722, 4726, 4740}:
        user_name, user_sid = _value(data, "TargetUserName"), _value(data, "TargetSid")
        extra.update(
            {
                "target_domain": _value(data, "TargetDomainName"),
                "subject_user": _value(data, "SubjectUserName"),
                "subject_domain": _value(data, "SubjectDomainName"),
            }
        )
        if record.event_id == 4740:
            reason = "locked"
            # In 4740 the "domain" field holds the computer the failed sign-ins came from.
            extra["caller_computer"] = extra.pop("target_domain")
    elif record.event_id in _GROUP_SCOPE:
        user_name, user_sid = _value(data, "SubjectUserName"), _value(data, "SubjectUserSid")
        extra.update(
            {
                "subject_domain": _value(data, "SubjectDomainName"),
                "group_name": _value(data, "TargetUserName"),
                "group_domain": _value(data, "TargetDomainName"),
                "group_sid": _value(data, "TargetSid"),
                "group_scope": _GROUP_SCOPE[record.event_id],
                "member_name": _value(data, "MemberName"),
                "member_sid": _value(data, "MemberSid"),
            }
        )
    elif record.event_id == 4688:
        return _process_created(record, data, extra, raw, position, log_source)
    else:  # 4672, 1102: the subject did it
        user_name, user_sid = _value(data, "SubjectUserName"), _value(data, "SubjectUserSid")
        extra["subject_domain"] = _value(data, "SubjectDomainName")
        if record.event_id == 4672:
            privileges = _value(data, "PrivilegeList")
            extra["privileges"] = " ".join(privileges.split()) if privileges else None
    ip = normalise_ip(ip_text)
    if ip_text and ip is None:
        extra["source_host"] = ip_text
    computer = _value({"c": record.computer or ""}, "c")
    return Event.model_validate(
        {
            "id": event_id(log_source, record.timestamp, raw, position),
            "timestamp": record.timestamp,
            "log_source": log_source,
            "event": {
                "action": action,
                "category": category,
                "outcome": outcome,
                "reason": reason,
            },
            "source": {"ip": ip, "host": None if ip else normalise_host(ip_text)},
            "user": {"name": user_name, "id": user_sid},
            "host": computer.lower() if computer else None,
            "raw": raw,
            "extra": {key: value for key, value in extra.items() if value is not None},
        }
    )


#: 4688 ``MandatoryLabel`` -> integrity level.
_LABELS = {
    "S-1-16-4096": "low",
    "S-1-16-8192": "medium",
    "S-1-16-8448": "medium",
    "S-1-16-12288": "high",
    "S-1-16-16384": "system",
}
#: 4688 ``TokenElevationType``.
_ELEVATION = {"%%1936": "full", "%%1937": "elevated", "%%1938": "limited"}


def _process_created(
    record: WindowsRecord,
    data: Mapping[str, str],
    extra: dict[str, object],
    raw: str,
    position: str,
    log_source: str,
) -> Event:
    """4688 (a new process), with the same ``process.*`` fields as Sysmon event 1."""
    image, parent = _value(data, "NewProcessName"), _value(data, "ParentProcessName")
    label = _value(data, "MandatoryLabel")
    extra.update(
        {
            "subject_domain": _value(data, "SubjectDomainName"),
            "elevation_type": _ELEVATION.get(_value(data, "TokenElevationType") or ""),
            "target_user": _value(data, "TargetUserName"),
        }
    )
    return _build(
        record,
        raw=raw,
        position=position,
        log_source=log_source,
        event={"action": "process.created", "category": "process", "outcome": "success"},
        user={"name": _value(data, "SubjectUserName"), "id": _value(data, "SubjectUserSid")},
        extra=extra,
        process={
            "pid": _int(data, "NewProcessId"),
            "name": base_name(image),
            "executable": image,
            "command_line": _value(data, "CommandLine"),
            "integrity_level": _LABELS.get(label or ""),
            "parent": {
                "pid": _int(data, "ProcessId"),
                "name": base_name(parent),
                "executable": parent,
            },
        },
    )


def _sysmon_event(record: WindowsRecord, *, raw: str, position: str, log_source: str) -> Event:
    data = dict(list(record.data.items())[:MAX_FIELDS])
    fields = sysmon_fields(record.event_id, data)
    source_ip = normalise_ip(fields.pop("source_ip", None))
    extra = {
        "event_id": record.event_id,
        "record_id": record.record_id,
        "channel": record.channel,
        **fields.pop("extra"),
    }
    return _build(
        record,
        raw=raw,
        position=position,
        log_source=log_source,
        user={"name": fields.pop("user_name")},
        source={"ip": source_ip},
        extra=extra,
        **fields,
    )


def _build(
    record: WindowsRecord,
    *,
    raw: str,
    position: str,
    log_source: str,
    extra: dict[str, object],
    **fields: object,
) -> Event:
    computer = _value({"c": record.computer or ""}, "c")
    return Event.model_validate(
        {
            "id": event_id(log_source, record.timestamp, raw, position),
            "timestamp": record.timestamp,
            "log_source": log_source,
            "host": computer.lower() if computer else None,
            "raw": raw,
            "extra": {key: value for key, value in extra.items() if value is not None},
            **fields,
        }
    )
