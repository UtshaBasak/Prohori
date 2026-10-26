"""Render an incident as Markdown, self-contained HTML, JSON or CSV.

Everything in an incident can come from attacker-controlled log lines or third-party data, so
every string is cleaned (control characters and ANSI escapes removed, whitespace collapsed,
length capped) before it reaches a template, and each format then neutralises its own markup:

* **HTML:** Jinja2 autoescaping, inline CSS only, a Content-Security-Policy that blocks scripts
  and external resources, and no links built from data.
* **Markdown:** every value is escaped by the template engine itself (``finalize``), so a
  template cannot forget; bare URLs and email addresses are broken so they do not become links.
* **CSV:** cells that a spreadsheet would treat as a formula are prefixed with ``'``.
* **JSON:** structured data; strings are cleaned the same way.
"""

import csv
import io
import json
import re
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from jinja2 import Environment, PackageLoader, StrictUndefined

from prohori.incidents.attack import map_attack
from prohori.parsers import sanitize
from prohori.rules.attack import ATTACK_VERSION
from prohori.schema import Incident, IndicatorType
from prohori.version import __version__

#: Longest text shown for one value in a report (the incident itself keeps up to 1,024).
MAX_TEXT = 500
#: Event ids listed per alert in the report.
MAX_EVENT_IDS = 10
#: JSON report format identifier.
REPORT_FORMAT = "prohori.report/1"

_SPACE_RE = re.compile(r"\s+")


class ReportFormat(StrEnum):
    MARKDOWN = "md"
    HTML = "html"
    JSON = "json"
    CSV = "csv"


@dataclass(frozen=True)
class ReportSource:
    """The incident file the report was rendered from."""

    name: str
    sha256: str


@dataclass(frozen=True)
class RedactionNote:
    """What was redacted, for the report's appendix."""

    users: bool
    ips: bool
    replaced: int


def clean(value: object, limit: int = MAX_TEXT) -> str:
    """Make untrusted text safe to place anywhere: one line, no control characters, capped."""
    text = sanitize(str(value)) if value is not None else ""
    text = _SPACE_RE.sub(" ", text).strip()
    if len(text) > limit:
        text = text[: limit - 1].rstrip() + "…"
    return text


# ---------------------------------------------------------------------- view model


def _fmt_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


def build_view(
    incident: Incident,
    *,
    source: ReportSource | None = None,
    redaction: RedactionNote | None = None,
) -> dict[str, Any]:
    """Everything a template shows, as cleaned plain data."""
    rules = Counter(a.detector_id for a in incident.alerts)
    titles = {a.detector_id: a.title for a in incident.alerts}
    mapping = map_attack(incident.attack)
    ips = [i.value for i in incident.indicators if i.type is IndicatorType.IP]
    accounts = sorted(
        {v for f, vs in incident.entities.items() if f in {"user.id", "user.name"} for v in vs}
    )
    provenance = incident.provenance
    rule_hashes = {r.id: r.sha256 for r in provenance.rules} if provenance else {}
    top = sorted(incident.score_breakdown, key=lambda c: -c.points)[:3]
    summary = (
        f"{incident.severity.value.capitalize()} incident (score {incident.score:g}, "
        f"{incident.confidence.value} confidence): {len(incident.alerts)} alert(s) from "
        f"{len(rules)} rule(s) between {_fmt_time(incident.first_seen)} and "
        f"{_fmt_time(incident.last_seen)}"
    )
    if ips:
        summary += f", from {_list(ips)}"
    if accounts:
        summary += f", involving {_list(accounts)}"
    summary += "."
    return {
        "id": clean(incident.id),
        "title": clean(incident.title),
        "status": incident.status.value,
        "severity": incident.severity.value,
        "score": f"{incident.score:g}",
        "confidence": incident.confidence.value,
        "first_seen": _fmt_time(incident.first_seen),
        "last_seen": _fmt_time(incident.last_seen),
        "summary": clean(summary, 1000),
        "key_factors": [clean(c.reason) for c in top if c.points > 0],
        "timeline": [
            {
                "time": _fmt_time(e.timestamp),
                "kind": "alert" if e.alert_id else "event",
                "description": clean(e.description),
                "ref": clean(e.alert_id or e.event_id or ""),
            }
            for e in incident.timeline
        ],
        "indicators": [
            {
                "type": i.type.value,
                "value": clean(i.value),
                "enrichment": [
                    {
                        "provider": clean(r.provider),
                        "retrieved": _fmt_time(r.retrieved_at),
                        "data": [(clean(k, 64), clean(v, 200)) for k, v in r.data.items()],
                        "note": clean(r.note) if r.note else "",
                    }
                    for r in i.enrichment
                ],
            }
            for i in incident.indicators
        ],
        "entities": [(clean(f, 64), [clean(v) for v in vs]) for f, vs in incident.entities.items()],
        "alerts": [
            {
                "rule": clean(a.detector_id),
                "title": clean(a.title),
                "severity": a.severity.value,
                "first_seen": _fmt_time(a.first_seen),
                "last_seen": _fmt_time(a.last_seen),
                "explanation": clean(a.explanation),
                "event_ids": [clean(e) for e in a.event_ids[-MAX_EVENT_IDS:]],
                "more_events": max(len(a.event_ids) - MAX_EVENT_IDS, 0),
            }
            for a in incident.alerts
        ],
        "attack_version": clean(incident.attack_version or ATTACK_VERSION),
        "tactics": [
            {
                "name": t.name,
                "techniques": [f"{x.id} {x.name}" for x in t.techniques],
            }
            for t in mapping.tactics
        ],
        "unverified_tags": [clean(t) for t in mapping.unverified],
        "score_breakdown": [(clean(c.reason), f"{c.points:+g}") for c in incident.score_breakdown],
        "actions": [clean(a) for a in incident.recommended_actions],
        "limitations": [clean(x) for x in incident.limitations],
        "appendix": {
            "rules": [
                {
                    "id": clean(r),
                    "title": clean(titles[r]),
                    "alerts": n,
                    "sha256": rule_hashes.get(r) or "",
                }
                for r, n in sorted(rules.items())
            ],
            "inputs": [
                {
                    "name": clean(i.name),
                    "sha256": i.sha256,
                    "bytes": i.bytes,
                    "events": i.events,
                    "parser": clean(i.parser),
                }
                for i in (provenance.inputs if provenance else ())
            ],
            "built_with": clean(
                f"{provenance.tool} {provenance.tool_version}" if provenance else "unknown"
            ),
            "enrichment": clean(provenance.enrichment if provenance else "unknown"),
            "rendered_with": f"prohori {__version__}",
            "source": {"name": clean(source.name), "sha256": source.sha256} if source else None,
            "redaction": _redaction_text(redaction),
        },
    }


def _list(values: list[str], limit: int = 3) -> str:
    shown = ", ".join(values[:limit])
    return shown if len(values) <= limit else f"{shown} and {len(values) - limit} more"


def _redaction_text(note: RedactionNote | None) -> str:
    if note is None:
        return "Not redacted: account names, ids and IP addresses are shown as logged."
    what = "account names, ids, email hashes and email addresses"
    if note.ips:
        what += " and IP addresses"
    return (
        f"Redacted: {what} are replaced by keyed pseudonyms (HMAC-SHA256 with a key that is "
        f"not stored; {note.replaced} value(s) replaced)."
    )


# ---------------------------------------------------------------------- Markdown


class MdSafe(str):
    """Markdown produced by our own helpers, passed through ``finalize`` unescaped."""

    __slots__ = ()


#: Characters that can start Markdown or HTML markup mid-line. Parentheses need no escape once
#: brackets are escaped (no link can form), and ``#`` / ``+`` only matter at a line start, which a
#: value never is.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~&@$])")


def md_escape(value: object) -> str:
    """Escape text so Markdown shows it literally: no links, HTML, emphasis or table breaks."""
    text = _MD_SPECIAL.sub(r"\\\1", clean(value))
    text = text.replace("://", ":\\/\\/").replace("www.", "www\\.")
    return re.sub(r"^(\d+)([.)])(?=\s|$)", r"\1\\\2", text)  # "1. x" must not start a list


def md_code(value: object) -> MdSafe:
    """A code span for identifiers (ids, IPs), safe inside table cells."""
    text = clean(value).replace("|", "\\|")
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") or not text else ""
    return MdSafe(f"{fence}{pad}{text}{pad}{fence}")


def _md_finalize(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, MdSafe):
        return str(value)
    return md_escape(value)


def _environment(*, html: bool) -> Environment:
    env = Environment(
        loader=PackageLoader("prohori.reports", "templates"),
        autoescape=html,  # noqa: S701 - Markdown is escaped by finalize instead
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    if not html:
        env.finalize = _md_finalize
        env.filters["code"] = md_code
    return env


# ---------------------------------------------------------------------- CSV

#: Formula prefixes, including the full-width forms some spreadsheets also accept.
_FULL_WIDTH = tuple(chr(code) for code in (0xFF1D, 0xFF0B, 0xFF0D, 0xFF20))  # = + - @
_FORMULA_START = ("=", "+", "-", "@", "\t", "\r", *_FULL_WIDTH)
CSV_COLUMNS = ("timestamp", "kind", "description", "event_id", "alert_id", "account", "source_ip")


def csv_cell(value: object) -> str:
    """Text a spreadsheet will show as text: formula-like cells get a leading apostrophe."""
    text = clean(value) if value is not None else ""
    return "'" + text if text.startswith(_FORMULA_START) else text


def _render_csv(incident: Incident) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for e in incident.timeline:
        writer.writerow(
            csv_cell(v)
            for v in (
                e.timestamp.isoformat().replace("+00:00", "Z"),
                "alert" if e.alert_id else "event",
                e.description,
                e.event_id,
                e.alert_id,
                e.account,
                e.source_ip,
            )
        )
    return out.getvalue()


# ---------------------------------------------------------------------- JSON


def _clean_tree(value: object) -> object:
    if isinstance(value, str):
        return clean(value, 4096)
    if isinstance(value, list):
        return [_clean_tree(v) for v in value]
    if isinstance(value, dict):
        return {clean(k, 256): _clean_tree(v) for k, v in value.items()}
    return value


def _render_json(incident: Incident, view: dict[str, Any]) -> str:
    document = {
        "format": REPORT_FORMAT,
        "summary": view["summary"],
        "attack": {"version": view["attack_version"], "tactics": view["tactics"]},
        "appendix": view["appendix"],
        "incident": _clean_tree(incident.model_dump(mode="json")),
    }
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


# ---------------------------------------------------------------------- entry point


def render(
    incident: Incident,
    fmt: ReportFormat,
    *,
    source: ReportSource | None = None,
    redaction: RedactionNote | None = None,
) -> str:
    """Render ``incident`` in ``fmt``. The output depends only on the arguments."""
    if fmt is ReportFormat.CSV:
        return _render_csv(incident)
    view = build_view(incident, source=source, redaction=redaction)
    if fmt is ReportFormat.JSON:
        return _render_json(incident, view)
    renderers: dict[ReportFormat, Callable[[], str]] = {
        ReportFormat.MARKDOWN: lambda: (
            _environment(html=False).get_template("report.md.j2").render(**view)
        ),
        ReportFormat.HTML: lambda: (
            _environment(html=True).get_template("report.html.j2").render(**view)
        ),
    }
    return renderers[fmt]()
