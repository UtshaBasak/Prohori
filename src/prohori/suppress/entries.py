# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Reviewed exceptions: who may silence what, why, until when (ADR-0043).

An :class:`Entry` names a detector (a rule id, a list of them, or ``*``), field matchers in the
rule syntax (``field|modifier: value``, a mapping or a list of mappings), a ``reason``, an
``owner`` and an ``expires`` date. It decides nothing about alerts by itself: it answers "does
this entry cover detector X?", "does this event match?" and "was it in force on day D?", so the
same entries serve the alert suppressions here and the endpoint policy's allow entries later.

An entry is in force up to and including its ``expires`` day (UTC). Whether it applies is
decided by the time of what it is applied to (an alert's last event), never by the clock, so a
replay of the same log makes the same decisions; the clock only drives the "expired" warning.
"""

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import Annotated, Self
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, model_validator

from prohori.rules.matching import RuleError, Selection, compile_selection
from prohori.rules.model import RULE_ID_PATTERN
from prohori.schema import Event, JsonScalar

#: Entry ids: lower case, digits, ``.``, ``_`` and ``-``; they appear in counters and reports.
ENTRY_ID_PATTERN = r"^[a-z0-9][a-z0-9_.-]{0,63}$"
#: ``rule: "*"`` covers every detector (rules and models).
ANY_RULE = "*"
MAX_ENTRIES = 1_000
MAX_ADDRESSES = 512

_CONFIG = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=True)


def _rule_id(value: str) -> str:
    if value != ANY_RULE and not re.fullmatch(RULE_ID_PATTERN, value):
        msg = f"invalid rule id {value!r}; use an id such as PRH-AUTH-001, or '*' for every rule"
        raise ValueError(msg)
    return value


def _timezone(value: str) -> str:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError):
        msg = f"unknown timezone {value!r}; use an IANA name such as UTC or Asia/Dhaka"
        raise ValueError(msg) from None
    return value


def _network(value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
    except ValueError:
        msg = f"invalid IP address or network {value!r}"
        raise ValueError(msg) from None
    return value


RuleRef = Annotated[str, Field(max_length=64), AfterValidator(_rule_id)]
EntryId = Annotated[str, Field(pattern=ENTRY_ID_PATTERN)]
Reason = Annotated[str, Field(min_length=3, max_length=500)]
Owner = Annotated[str, Field(min_length=1, max_length=200)]
Network = Annotated[str, Field(max_length=64), AfterValidator(_network)]


class _Common(BaseModel):
    model_config = _CONFIG

    id: EntryId
    reason: Reason
    owner: Owner
    expires: date


class EntryDocument(_Common):
    """One entry as written; ``match`` is compiled separately (rule-style errors and lines)."""

    rule: RuleRef | Annotated[list[RuleRef], Field(min_length=1, max_length=64)]
    match: object
    timezone: Annotated[str, Field(max_length=64), AfterValidator(_timezone)] = "UTC"

    @property
    def rules(self) -> tuple[str, ...]:
        return (self.rule,) if isinstance(self.rule, str) else tuple(self.rule)

    @model_validator(mode="after")
    def _star_alone(self) -> Self:
        if ANY_RULE in self.rules and len(self.rules) > 1:
            msg = "'*' already covers every rule; do not list rules next to it"
            raise ValueError(msg)
        return self


class AllowIpDocument(_Common):
    """Addresses whose activity is known to be benign: no alert, no reputation points."""

    addresses: Annotated[list[Network], Field(min_length=1, max_length=MAX_ADDRESSES)]


@dataclass(frozen=True)
class Entry:
    """A compiled entry: covers some detectors, matches events, in force until ``expires``."""

    id: str
    rules: tuple[str, ...]
    selection: Selection
    reason: str
    owner: str
    expires: date
    #: Set for an ``allow_ips`` entry: the addresses also get no reputation points.
    networks: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = ()

    @property
    def allows_ips(self) -> bool:
        return bool(self.networks)

    def covers(self, detector_id: str) -> bool:
        """Whether this entry applies to alerts from ``detector_id``."""
        return self.rules == (ANY_RULE,) or detector_id in self.rules

    def in_force(self, when: datetime) -> bool:
        """Whether the entry applies to something that happened at ``when`` (UTC days)."""
        return when.astimezone(UTC).date() <= self.expires

    def expired(self, today: date) -> bool:
        return today > self.expires

    def matches(self, event: Event) -> bool:
        return self.selection.matches(event)

    def matches_values(self, values: Mapping[str, JsonScalar]) -> bool:
        """Whether ``values`` (field -> value, such as an alert's entities) match.

        Only a group whose every field is in ``values`` can match: a field that is not there is
        unknown, never "missing", so it never counts as a match.
        """
        return any(
            all(m.field in values for m in group)
            and all(m.matches_value(values[m.field]) for m in group)
            for group in self.selection.groups
        )

    def allows_ip(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip.version == n.version and ip in n for n in self.networks)


def compile_entry(
    document: EntryDocument, path: tuple[str | int, ...], errors: list[RuleError]
) -> Entry | None:
    """Compile one ``suppressions`` entry; append problems (with their paths) to ``errors``."""
    if document.rules == (ANY_RULE,) and not document.match:
        errors.append(RuleError((*path, "match"), "a '*' entry needs field matchers"))
        return None
    selection = compile_selection(
        document.id, document.match, (*path, "match"), errors, ZoneInfo(document.timezone)
    )
    if selection is None:
        return None
    return Entry(
        id=document.id,
        rules=document.rules,
        selection=selection,
        reason=document.reason,
        owner=document.owner,
        expires=document.expires,
    )


def compile_allow(document: AllowIpDocument) -> Entry:
    """An ``allow_ips`` entry: every detector, any of the addresses as ``source.ip``."""
    networks = tuple(ipaddress.ip_network(a, strict=False) for a in document.addresses)
    errors: list[RuleError] = []
    selection = compile_selection(
        document.id, {"source.ip|cidr": [str(n) for n in networks]}, (), errors
    )
    if selection is None:  # pragma: no cover - the addresses were validated above
        msg = "; ".join(e.message for e in errors)
        raise ValueError(msg)
    return Entry(
        id=document.id,
        rules=(ANY_RULE,),
        selection=selection,
        reason=document.reason,
        owner=document.owner,
        expires=document.expires,
        networks=networks,
    )
