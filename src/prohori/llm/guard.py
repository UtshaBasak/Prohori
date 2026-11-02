"""Safeguards around the model: fencing untrusted text in, validating answers out.

**Fencing.** Text that can come from logs (titles and explanations that quote log values, score
reasons, limitations, entity and indicator values) is wrapped as ``⟦u:NONCE⟧text⟦/u:NONCE⟧``
with a random nonce per request. The characters ``⟦`` and ``⟧`` are removed from the text first,
so it cannot close the fence early or forge one. The system instruction says that fenced text is
data and that instructions inside it must be ignored.

**Validation.** Every IP address, email address, pseudonym, incident id, rule id and ATT&CK
technique id an answer mentions must appear in the incident's *structured* fields (never its
free text, which an attacker can fill) or in the sources the model was given; any link must
point to attack.mitre.org. Validation is conservative: one unknown value rejects the answer.
"""

import ipaddress
import re
import secrets
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

FENCE_CHARS = str.maketrans("", "", "⟦⟧")
_FENCE_RE = re.compile(r"⟦u:[0-9a-f]{8}⟧.*?⟦/u:[0-9a-f]{8}⟧", re.DOTALL)

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]?\d)")
_IPV6 = re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}(?![\w:])")
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
_PSEUDONYM = re.compile(r"\[(?:user|email|ip):[0-9a-f]{10}\]")
_INCIDENT = re.compile(r"\bINC-[A-Za-z0-9]{6,40}\b")
_RULE = re.compile(r"\b[A-Z]{2,10}-[A-Z]{2,10}-\d{3}\b")
_TECHNIQUE = re.compile(r"(?<![A-Za-z0-9])[Tt]\d{4}(?:\.\d{3})?(?![\d.]*\d)")
_URL = re.compile(r"https?://[^\s<>()\[\]\"'`]+", re.IGNORECASE)
TRUSTED_LINK_HOSTS = frozenset({"attack.mitre.org"})
#: Entity fields whose values an answer may cite: addresses and (pseudonymised) accounts.
IDENTITY_KEYS = frozenset(
    {"source.ip", "destination.ip", "client.ip", "user.id", "user.name", "user.email_hash"}
)


def new_nonce() -> str:
    return secrets.token_hex(4)


def fence(text: str, nonce: str) -> str:
    """Wrap untrusted ``text`` so the model can tell it from instructions."""
    return f"⟦u:{nonce}⟧{text.translate(FENCE_CHARS)}⟦/u:{nonce}⟧"


def outside_fences(text: str) -> str:
    """``text`` with every fenced segment removed (what the model should treat as instructions)."""
    return _FENCE_RE.sub(" ", text)


def _ips(text: str) -> set[str]:
    found = set()
    for regex in (_IPV4, _IPV6):
        for match in regex.finditer(text):
            try:
                found.add(str(ipaddress.ip_address(match.group())))
            except ValueError:
                continue
    return found


def techniques(text: str) -> set[str]:
    return {m.group().upper() for m in _TECHNIQUE.finditer(text)}


@dataclass
class Allowed:
    """The values an answer may cite."""

    ips: set[str] = field(default_factory=set)
    emails: set[str] = field(default_factory=set)
    pseudonyms: set[str] = field(default_factory=set)
    incidents: set[str] = field(default_factory=set)
    rules: set[str] = field(default_factory=set)
    techniques: set[str] = field(default_factory=set)

    def add_text(self, text: str) -> None:
        """Allow every citable value in ``text`` (use only for trusted text)."""
        self.ips |= _ips(text)
        self.emails |= {m.lower() for m in _EMAIL.findall(text)}
        self.pseudonyms |= set(_PSEUDONYM.findall(text))
        self.incidents |= set(_INCIDENT.findall(text))
        self.rules |= set(_RULE.findall(text))
        self.techniques |= techniques(text)


def allowed_from(data: Mapping[str, Any], sources: Iterable[str] = ()) -> Allowed:
    """What an answer about ``data`` (a payload) may cite: structured fields and sources only."""
    allowed = Allowed()
    if data:
        allowed.incidents.add(str(data["id"]))
        allowed.rules |= {str(a["rule"]) for a in data["alerts"]}
        allowed.techniques |= techniques(" ".join(data["attack"]))
        for alert in data["alerts"]:
            allowed.techniques |= techniques(" ".join(alert["attack"]))
        # Only identity fields: an IP address or a pseudonym, never free text such as a user agent.
        values = [
            (key, v) for key, vs in data["entities"].items() for v in vs if key in IDENTITY_KEYS
        ]
        values += [(f"indicator.{i['type']}", i["value"]) for i in data["indicators"]]
        for key, value in values:
            text = str(value).translate(FENCE_CHARS).strip()
            if key.endswith("ip"):
                if _PSEUDONYM.fullmatch(text):
                    allowed.pseudonyms.add(text)
                else:
                    allowed.ips |= {ip for ip in _ips(text) if ip == text or f"[{ip}]" == text}
            elif _PSEUDONYM.fullmatch(text):
                allowed.pseudonyms.add(text)
    for text in sources:
        allowed.add_text(text)
    return allowed


@dataclass(frozen=True)
class Verdict:
    unknown: dict[str, list[str]]

    @property
    def ok(self) -> bool:
        return not self.unknown

    def describe(self, limit: int = 8) -> str:
        parts = [f"{kind} {', '.join(values[:limit])}" for kind, values in self.unknown.items()]
        return "; ".join(parts)


def validate(answer: str, allowed: Allowed) -> Verdict:
    """Find what ``answer`` cites that ``allowed`` does not contain."""
    unknown: dict[str, list[str]] = {}

    def check(kind: str, found: Iterable[str], known: set[str]) -> None:
        missing = sorted(set(found) - known)
        if missing:
            unknown[kind] = [m[:80] for m in missing]

    urls = _URL.findall(answer)
    check("links", [u for u in urls if urlsplit(u).hostname not in TRUSTED_LINK_HOSTS], set())
    text = _URL.sub(" ", answer)  # an address inside a trusted link is not cited on its own
    check("IP addresses", _ips(text), allowed.ips)
    check("email addresses", {m.lower() for m in _EMAIL.findall(text)}, allowed.emails)
    check("pseudonyms", _PSEUDONYM.findall(text), allowed.pseudonyms)
    check("incident ids", _INCIDENT.findall(text), allowed.incidents)
    check("rule ids", _RULE.findall(text), allowed.rules)
    check("ATT&CK techniques", techniques(text) | techniques_in_links(urls), allowed.techniques)
    return Verdict(unknown)


def techniques_in_links(urls: Iterable[str]) -> set[str]:
    found = set()
    for url in urls:
        parts = urlsplit(url)
        if parts.hostname in TRUSTED_LINK_HOSTS:
            found |= techniques(parts.path.replace("/", "."))
    return found
