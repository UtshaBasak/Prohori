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
The answer is checked after Unicode normalisation (NFKC, so full-width digits and dots count)
and with defanged forms such as ``198[.]51[.]100[.]9`` and ``hxxp://`` turned back. Markdown link
and image targets and scheme-less ``//host`` links count as links, and an address that looks
like IPv4 but does not parse (``198.051.100.009``) counts as unknown.
"""

import ipaddress
import re
import secrets
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

FENCE_CHARS = str.maketrans("", "", "⟦⟧")
_FENCE_RE = re.compile(r"⟦u:[0-9a-f]{8}⟧.*?⟦/u:[0-9a-f]{8}⟧", re.DOTALL)

_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]?\d)")
# Any run of hex digits and colons with at least two colons: compressed forms (2001:db8::1, ::1)
# included. Candidates are kept only if ipaddress parses them.
_IPV6 = re.compile(r"(?<![\w:.])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%\w+)?(?![\w:])")
_EMAIL = re.compile(r"[\w.%+-]+@[\w-]+(?:\.[\w-]+)*\.[^\W\d_]{2,}")
_PSEUDONYM = re.compile(r"\[(?:user|email|ip):[0-9a-f]{10}\]")
_INCIDENT = re.compile(r"\bINC-[A-Za-z0-9]{6,40}\b")
# Rule ids such as PRH-AUTH-001, and Prohori's detector ids (PRH-ML-ZSCORE) in any case.
_RULE = re.compile(r"\b(?:[A-Z]{2,10}-[A-Z]{2,10}-\d{3}|(?i:PRH-[A-Z]{2,10}-[A-Z0-9]{2,12}))\b")
_TECHNIQUE = re.compile(r"(?<![A-Za-z0-9])[Tt]\d{4}(?:\.\d{3})?(?![\d.]*\d)")
_URL = re.compile(r"(?:[a-z][a-z0-9+.-]*:)?//[^\s<>()\[\]\"'`]+", re.IGNORECASE)
# Markdown link and image targets: [text](target) and ![alt](target).
_MARKDOWN_TARGET = re.compile(r"\]\(\s*<?([^)\s>]+)")
_DEFANGED = (("[.]", "."), ("(.)", "."), ("[dot]", "."), ("[:]", ":"), ("hxxp", "http"))
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


def _ips(text: str, *, strict: bool = False) -> set[str]:
    """IP addresses in ``text``, normalised. With ``strict``, a dotted quad that does not parse
    (such as ``198.051.100.009``, which some tools read as octal) is returned as it is, so it
    can never be in an allow-list.
    """
    found = set()
    for regex in (_IPV4, _IPV6):
        for match in regex.finditer(text):
            candidate = match.group()
            try:
                found.add(str(ipaddress.ip_address(candidate.split("%", 1)[0])))
            except ValueError:
                if strict and regex is _IPV4 and all(int(o) <= 255 for o in candidate.split(".")):
                    found.add(candidate)
    return found


def normalise(text: str) -> str:
    """``text`` as it is checked: NFKC-normalised, with defanged addresses and links undone."""
    text = unicodedata.normalize("NFKC", text).replace("。", ".")
    for defanged, plain in _DEFANGED:
        text = re.sub(re.escape(defanged), plain, text, flags=re.IGNORECASE)
    return text


def _trusted_link(url: str) -> bool:
    if "\\" in url:  # browsers read a backslash as a slash: https://evil\@attack.mitre.org/
        return False
    parts = urlsplit(url)
    return parts.scheme.lower() == "https" and parts.hostname in TRUSTED_LINK_HOSTS


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
        self.rules |= {m.upper() for m in _RULE.findall(text)}
        self.techniques |= techniques(text)


def allowed_from(data: Mapping[str, Any], sources: Iterable[str] = ()) -> Allowed:
    """What an answer about ``data`` (a payload) may cite: structured fields and sources only."""
    allowed = Allowed()
    if data:
        allowed.incidents.add(str(data["id"]))
        allowed.rules |= {str(a["rule"]).upper() for a in data["alerts"]}
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

    answer = normalise(answer)
    urls = _URL.findall(answer)
    targets = [t for t in _MARKDOWN_TARGET.findall(answer) if not t.startswith("#")]
    check("links", [u for u in [*urls, *targets] if not _trusted_link(u)], set())
    text = _URL.sub(" ", answer)  # an address inside a trusted link is not cited on its own
    check("IP addresses", _ips(text, strict=True), allowed.ips)
    check("email addresses", {m.lower() for m in _EMAIL.findall(text)}, allowed.emails)
    check("pseudonyms", _PSEUDONYM.findall(text), allowed.pseudonyms)
    check("incident ids", _INCIDENT.findall(text), allowed.incidents)
    check("rule ids", {m.upper() for m in _RULE.findall(text)}, allowed.rules)
    check("ATT&CK techniques", techniques(text) | techniques_in_links(urls), allowed.techniques)
    return Verdict(unknown)


def techniques_in_links(urls: Iterable[str]) -> set[str]:
    found = set()
    for url in urls:
        parts = urlsplit(url)
        if _trusted_link(url):
            found |= techniques(parts.path.replace("/", "."))
    return found
