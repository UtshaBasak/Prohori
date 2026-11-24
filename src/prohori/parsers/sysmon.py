# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Sysmon events -> common-schema events (the Sysmon half of :mod:`prohori.parsers.windows`).

Field names follow Sysmon's own event schema as Sysmon 13 to 15 write it (schema 4.50 to 4.91);
older versions leave fields such as ``RuleName``, ``User`` or ``ParentUser`` out, which only
leaves the matching event fields unset. Sysmon configurations decide which events exist at all,
so a missing event type is never an error.

=====  =================================  ========  ========================================
Event  ``event.action``                   Category  Main fields
=====  =================================  ========  ========================================
1      ``process.created``                process   ``process.*``, ``process.parent.*``
3      ``network.connection``             network   ``process.*``, ``destination.*``
7      ``process.image_loaded``           process   ``process.*``, ``file.path`` (the DLL)
8      ``process.remote_thread_created``  process   ``process.*`` (source), target in extra
10     ``process.accessed``               process   ``process.*`` (source), target in extra
11     ``file.created``                   file      ``process.*``, ``file.*``
12     ``registry.key_created``, ...      registry  ``process.*``, ``registry.path``
13     ``registry.value_set``             registry  ``registry.path``, ``.value``, ``.data``
14     ``registry.renamed``               registry  ``registry.path``, new name in extra
22     ``dns.query``                      dns       ``process.*``, ``dns.question``
23     ``file.deleted``                   file      ``process.*``, ``file.*`` (archived)
26     ``file.deleted``                   file      ``process.*``, ``file.*`` (logged only)
=====  =================================  ========  ========================================
"""

import re
from collections.abc import Mapping
from typing import Any

from prohori.parsers.base import ParseError
from prohori.parsers.util import normalise_host, normalise_ip

SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

_ACTIONS: Mapping[int, tuple[str, str]] = {
    1: ("process.created", "process"),
    3: ("network.connection", "network"),
    7: ("process.image_loaded", "process"),
    8: ("process.remote_thread_created", "process"),
    10: ("process.accessed", "process"),
    11: ("file.created", "file"),
    12: ("registry.changed", "registry"),
    13: ("registry.value_set", "registry"),
    14: ("registry.renamed", "registry"),
    22: ("dns.query", "dns"),
    23: ("file.deleted", "file"),
    26: ("file.deleted", "file"),
}
#: Sysmon event ids that are mapped (others are skipped).
SYSMON_EVENT_IDS = frozenset(_ACTIONS)

_REGISTRY_ACTIONS = {
    "createkey": "registry.key_created",
    "deletekey": "registry.key_deleted",
    "createvalue": "registry.value_created",
    "deletevalue": "registry.value_deleted",
}
_SHA256_RE = re.compile(r"(?:^|,)SHA256=([0-9A-Fa-f]{64})(?:,|$)")
_INTEGRITY = {"low", "medium", "high", "system", "appcontainer", "untrusted"}


def _value(data: Mapping[str, str], name: str) -> str | None:
    value = data.get(name)
    if value is None:
        return None
    value = value.strip()
    return None if value in {"", "-"} else value


def _pid(data: Mapping[str, str], name: str) -> int | None:
    value = _value(data, name)
    if value is None:
        return None
    try:
        number = int(value, 16) if value.lower().startswith("0x") else int(value)
    except ValueError:
        raise ParseError(f"{name} is not a process id: {value[:40]!r}") from None
    if not 0 <= number < 2**32:
        raise ParseError(f"{name} out of range: {number}")
    return number


def base_name(path: str | None) -> str | None:
    """The last part of a Windows or POSIX path (``C:\\Windows\\cmd.exe`` -> ``cmd.exe``)."""
    if not path:
        return None
    name = re.split(r"[\\/]", path)[-1]
    return name or None


def sha256_of(hashes: str | None) -> str | None:
    """The SHA-256 in Sysmon's ``Hashes`` field (``SHA1=..,MD5=..,SHA256=..``), lower case."""
    if not hashes:
        return None
    match = _SHA256_RE.search(hashes)
    return match[1].lower() if match else None


def split_user(value: str | None) -> tuple[str | None, str | None]:
    """``DOMAIN\\name`` -> (``name``, ``DOMAIN``)."""
    if not value:
        return None, None
    domain, sep, name = value.rpartition("\\")
    return (name or None, domain or None) if sep else (value, None)


def integrity(value: str | None) -> str | None:
    """Sysmon's ``IntegrityLevel`` in lower case, when it is one of Windows' levels."""
    if value is None:
        return None
    level = value.strip().lower()
    return level if level in _INTEGRITY else None


def _extension(path: str | None) -> str | None:
    name = base_name(path)
    if not name or "." not in name.strip("."):
        return None
    return name.rsplit(".", 1)[1].lower() or None


def process_fields(
    data: Mapping[str, str], prefix: str = "", *, created: bool = False
) -> dict[str, Any]:
    """``process.*`` from Sysmon's ``Image``/``ProcessId``/... (``Source``-prefixed for 8, 10).

    Only a process creation (event 1) describes the process itself (command line, hash,
    integrity); in other events ``Hashes`` is the hash of a file or a loaded image.
    """
    image = _value(data, f"{prefix}Image")
    return {
        "pid": _pid(data, f"{prefix}ProcessId"),
        "name": base_name(image),
        "executable": image,
        "command_line": _value(data, "CommandLine") if created else None,
        "hash": sha256_of(_value(data, "Hashes")) if created else None,
        "integrity_level": integrity(_value(data, "IntegrityLevel")) if created else None,
    }


def sysmon_fields(event_id: int, data: Mapping[str, str]) -> dict[str, Any]:
    """Every event field a Sysmon record gives (``event``, ``process``, ``file``, ``extra``...)."""
    action, category = _ACTIONS[event_id]
    extra: dict[str, object] = {
        "rule_name": _value(data, "RuleName"),
        "process_guid": _value(data, "ProcessGuid"),
    }
    fields: dict[str, Any] = {}
    source_side = event_id in {8, 10}
    process = process_fields(data, "Source" if source_side else "", created=event_id == 1)
    user_name, user_domain = split_user(_value(data, "SourceUser" if source_side else "User"))
    if event_id == 1:
        parent_image = _value(data, "ParentImage")
        process["parent"] = {
            "pid": _pid(data, "ParentProcessId"),
            "name": base_name(parent_image),
            "executable": parent_image,
            "command_line": _value(data, "ParentCommandLine"),
        }
        extra.update(
            {
                "parent_process_guid": _value(data, "ParentProcessGuid"),
                "current_directory": _value(data, "CurrentDirectory"),
                "original_file_name": _value(data, "OriginalFileName"),
                "description": _value(data, "Description"),
                "company": _value(data, "Company"),
                "logon_id": _value(data, "LogonId"),
                "hashes": _value(data, "Hashes"),
            }
        )
    elif event_id == 3:
        destination_ip = _value(data, "DestinationIp")
        ip = normalise_ip(destination_ip)
        fields["destination"] = {
            "ip": str(ip) if ip is not None else None,
            "port": _pid(data, "DestinationPort"),
            "domain": normalise_host(_value(data, "DestinationHostname")),
        }
        fields["source_ip"] = _value(data, "SourceIp")
        extra.update(
            {
                "transport": (_value(data, "Protocol") or "").lower() or None,
                "source_port": _pid(data, "SourcePort"),
                "initiated": _value(data, "Initiated"),
            }
        )
    elif event_id == 7:
        loaded = _value(data, "ImageLoaded")
        fields["file"] = {
            "path": loaded,
            "name": base_name(loaded),
            "extension": _extension(loaded),
        }
        extra.update(
            {
                "signed": _value(data, "Signed"),
                "signature": _value(data, "Signature"),
                "signature_status": _value(data, "SignatureStatus"),
                "hashes": _value(data, "Hashes"),
            }
        )
    elif source_side:
        target = _value(data, "TargetImage")
        extra.update(
            {
                "process_guid": _value(data, "SourceProcessGUID")
                or _value(data, "SourceProcessGuid"),
                "target_image": target,
                "target_name": base_name(target),
                "target_pid": _pid(data, "TargetProcessId"),
                "target_user": _value(data, "TargetUser"),
            }
        )
        if event_id == 10:
            extra["granted_access"] = _value(data, "GrantedAccess")
            call_trace = _value(data, "CallTrace")
            extra["call_trace"] = call_trace[:1024] if call_trace else None
        else:
            extra["start_module"] = _value(data, "StartModule")
            extra["start_function"] = _value(data, "StartFunction")
    elif event_id in {11, 23, 26}:
        path = _value(data, "TargetFilename")
        fields["file"] = {"path": path, "name": base_name(path), "extension": _extension(path)}
        extra["hashes"] = _value(data, "Hashes")
        if event_id == 23:
            extra["archived"] = _value(data, "Archived") or "true"
        elif event_id == 26:
            extra["archived"] = "false"
    elif event_id in {12, 13, 14}:
        path = _value(data, "TargetObject")
        event_type = (_value(data, "EventType") or "").lower()
        if event_id == 12:
            action = _REGISTRY_ACTIONS.get(event_type, action)
        fields["registry"] = {
            "path": path,
            "value": base_name(path) if event_id == 13 else None,
            "data": _value(data, "Details") if event_id == 13 else None,
        }
        extra["new_name"] = _value(data, "NewName")
    elif event_id == 22:
        fields["dns"] = {"question": _value(data, "QueryName")}
        extra.update(
            {
                "query_status": _value(data, "QueryStatus"),
                "query_results": _value(data, "QueryResults"),
            }
        )
    extra["user_domain"] = user_domain
    fields.update(
        {
            "event": {"action": action, "category": category, "outcome": "success"},
            "process": process,
            "user_name": user_name,
            "extra": extra,
        }
    )
    return fields
