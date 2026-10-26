"""Redaction for shareable reports: replace account names, ids, emails and optionally IPs.

Values are replaced by keyed pseudonyms such as ``[user:3f2a9c1e07]`` (HMAC-SHA256 with a key
that is never written out), so one account keeps one pseudonym throughout a report but cannot be
looked up. Values are collected from every structured field (entities, alert entities, timeline
accounts and addresses, indicators) and then replaced in **every** string of the incident, since
the same values appear in titles, explanations, score reasons and limitations. Email addresses
(and, with ``ips``, IP addresses) are also found by pattern in free text.

After rendering, :func:`find_leaks` checks the output for any original value; the report command
refuses to write a report that still contains one.
"""

import hashlib
import hmac
import ipaddress
import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import TypeAlias

from prohori.schema import Incident, IndicatorType

Json: TypeAlias = dict[str, "Json"] | list["Json"] | str | int | float | bool | None

#: Entity fields whose values identify a person's account.
USER_FIELDS = frozenset({"user.id", "user.name", "user.email_hash"})
IP_FIELDS = frozenset({"source.ip"})

#: Keys whose values are structural (ids, hashes, enums, times) and never personal data.
_STRUCTURAL_KEYS = frozenset(
    {
        "id",
        "event_ids",
        "event_id",
        "alert_id",
        "detector_id",
        "detector_kind",
        "attack",
        "attack_version",
        "severity",
        "status",
        "confidence",
        "type",
        "provider",
        "retrieved_at",
        "timestamp",
        "first_seen",
        "last_seen",
        "sha256",
        "tool",
        "tool_version",
        "parser",
        "enrichment",
    }
)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w])")
_IPV6_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![\w:])")
_PSEUDONYM_RE = re.compile(r"\[(?:user|email|ip):[0-9a-f]{10}\]")


def _tokens(values: Iterable[str]) -> re.Pattern[str]:
    """Match any of ``values`` as a whole token: not inside a longer word or a dotted name.

    ``admin`` matches in "account admin." but not in "admin.role.granted" or "PRH-ADMIN-001".
    Longer values are tried first, so one value inside another is not replaced twice.
    """
    alternatives = "|".join(re.escape(v) for v in sorted(set(values), key=lambda v: (-len(v), v)))
    return re.compile(r"(?<![\w@-])(?<!\w\.)(?:" + alternatives + r")(?![\w@-])(?!\.\w)")


@dataclass
class Redactor:
    """Replaces personal values in an incident with keyed pseudonyms."""

    key: bytes
    ips: bool = False
    replaced: dict[str, str] = field(default_factory=dict)  # original -> pseudonym

    def __post_init__(self) -> None:
        if len(self.key) < 16:
            msg = "the redaction key must be at least 16 bytes"
            raise ValueError(msg)

    def pseudonym(self, kind: str, value: str) -> str:
        digest = hmac.new(self.key, f"{kind}\x1f{value}".encode(), hashlib.sha256).hexdigest()
        return f"[{kind}:{digest[:10]}]"

    def redact(self, incident: Incident) -> Incident:
        """Return a copy of ``incident`` with personal values replaced."""
        data = incident.model_dump(mode="json")
        self._collect(incident, data)
        if not self.replaced:
            return incident
        pattern = _tokens(self.replaced)

        def replace(text: str) -> str:  # one pass: pseudonyms are never re-scanned
            return pattern.sub(lambda m: self.replaced[m.group()], text)

        return Incident.model_validate(_walk(data, replace))

    def _collect(self, incident: Incident, data: Json) -> None:
        def add(kind: str, value: str | None) -> None:
            if value and value not in self.replaced:
                self.replaced[value] = self.pseudonym(kind, value)

        entity_maps: list[Mapping[str, tuple[str, ...]]] = [
            incident.entities,
            *({k: (v,) for k, v in a.entities.items()} for a in incident.alerts),
        ]
        for entities in entity_maps:
            for name, values in entities.items():
                for value in values:
                    if name in USER_FIELDS:
                        add("user", value)
                    elif self.ips and name in IP_FIELDS:
                        add("ip", value)
        for entry in incident.timeline:
            add("user", entry.account)
            if self.ips:
                add("ip", entry.source_ip)
        for indicator in incident.indicators:
            if indicator.type is IndicatorType.USER:
                add("user", indicator.value)
            elif self.ips and indicator.type is IndicatorType.IP:
                add("ip", indicator.value)
        for text in _strings(data):
            for match in _EMAIL_RE.finditer(text):
                add("email", match.group())
            if self.ips:
                for found in _addresses(text):
                    add("ip", found)


def _addresses(text: str) -> Iterator[str]:
    for regex in (_IPV4_RE, _IPV6_RE):
        for match in regex.finditer(text):
            candidate = match.group()
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                continue
            yield candidate


def _walk(value: Json, transform: Callable[[str], str], key: str | None = None) -> Json:
    if key in _STRUCTURAL_KEYS:
        return value
    if isinstance(value, str):
        return transform(value)
    if isinstance(value, list):
        return [_walk(item, transform, key) for item in value]
    if isinstance(value, dict):
        return {k: _walk(v, transform, k) for k, v in value.items()}
    return value


def _strings(value: Json, key: str | None = None) -> Iterator[str]:
    if key in _STRUCTURAL_KEYS:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item, key)
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _strings(v, k)


def find_leaks(text: str, originals: Iterable[str]) -> list[str]:
    """Return the original values that still occur in ``text`` as whole tokens.

    Pseudonyms are removed first, so a value such as ``user`` does not match ``[user:...]``.
    """
    values = [v for v in originals if v]
    if not values:
        return []
    return sorted(set(_tokens(values).findall(_PSEUDONYM_RE.sub(" ", text))))


def is_pseudonym(text: str) -> bool:
    return bool(_PSEUDONYM_RE.fullmatch(text))
