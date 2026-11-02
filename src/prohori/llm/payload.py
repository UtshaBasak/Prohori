"""What is sent to an LLM about an incident: an allow-list of fields, redacted, size-capped.

The payload is built from chosen fields, never by dumping the incident:

- **Redaction first.** Account names, ids and email addresses are replaced with keyed pseudonyms
  (:class:`prohori.reports.redact.Redactor`; the key is random per run and never written), and IP
  addresses too with ``mask_ips``. The pseudonyms are mapped back only on this machine, in the
  answer that is shown.
- **No log content.** Incidents hold no raw log lines, and the timeline's event descriptions,
  which carry attacker-controlled request paths and user agents, are not sent: only the number of
  events and the alert entries, which Prohori writes itself. Free-text fields are capped.
- **Fenced.** In the text sent, every value that can carry log content is wrapped in a fence
  with a random nonce (:func:`prohori.llm.guard.fence`); :attr:`Payload.data` keeps the plain
  values, from which :func:`prohori.llm.guard.allowed_from` takes what an answer may cite.
- **Size cap.** The estimated size (characters / 4) is kept under ``max_input_tokens`` by
  dropping, in this order, indicators beyond the first five, alerts beyond the first twenty and
  the alert timeline; the payload says what was trimmed.
- **Leak check.** The exact text that would be sent is searched for every replaced value (on
  decoded text, so non-ASCII names count). If one remains, :class:`RedactionError` is raised and
  nothing is sent.
"""

import json
import re
import secrets
from dataclasses import dataclass
from typing import Any

from prohori.llm.guard import fence, new_nonce
from prohori.reports.redact import Redactor, find_leaks
from prohori.schema import Incident

#: Longest free-text value sent (titles, explanations, reasons, actions, limitations).
MAX_TEXT = 300
FORMAT = "prohori.llm-payload/1"


class RedactionError(ValueError):
    """The payload would still contain a personal value; nothing may be sent."""


@dataclass(frozen=True)
class Payload:
    """The redacted incident as sent, and the local map back from pseudonyms."""

    data: dict[str, Any]  # plain values
    text: str  # exactly what goes into the prompt, with untrusted values fenced
    pseudonyms: dict[str, str]  # pseudonym -> original, kept on this machine
    trimmed: tuple[str, ...]
    nonce: str = ""

    @property
    def estimated_tokens(self) -> int:
        return estimate_tokens(self.text)

    def restore(self, answer: str) -> str:
        """Put the original values back in ``answer`` for local display (exact tokens only)."""
        if not self.pseudonyms:
            return answer
        pattern = re.compile("|".join(re.escape(p) for p in self.pseudonyms))
        return pattern.sub(lambda m: self.pseudonyms[m.group()], answer)


def estimate_tokens(text: str) -> int:
    return len(text) // 4 + 1


def _cap(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= MAX_TEXT else text[: MAX_TEXT - 1] + "…"


def build_payload(
    incident: Incident,
    *,
    mask_ips: bool = False,
    max_input_tokens: int = 6000,
    nonce: str | None = None,
) -> Payload:
    """Redact ``incident`` and build the payload to send.

    Raises:
        RedactionError: if a replaced value would still be sent.
    """
    nonce = nonce or new_nonce()
    redactor = Redactor(secrets.token_bytes(32), ips=mask_ips)
    clean = redactor.redact(incident)
    data = _fields(clean)
    trimmed: list[str] = []
    text = _serialise(_fenced(data, nonce))
    for step in ("indicators", "alerts", "alert_timeline"):
        if estimate_tokens(text) <= max_input_tokens:
            break
        if _trim(data, step):
            trimmed.append(step)
            data["trimmed"] = list(trimmed)
            text = _serialise(_fenced(data, nonce))
    leaks = find_leaks(text, redactor.replaced)
    if leaks:
        raise RedactionError(f"{len(leaks)} personal value(s) would still be sent")
    return Payload(
        data=data,
        text=text,
        pseudonyms={v: k for k, v in redactor.replaced.items()},
        trimmed=tuple(trimmed),
        nonce=nonce,
    )


def _fenced(data: dict[str, Any], nonce: str) -> dict[str, Any]:
    """A copy of ``data`` with every value that can carry log content fenced."""

    def f(value: str | None) -> str | None:
        return fence(value, nonce) if value else value

    copy: dict[str, Any] = json.loads(json.dumps(data))
    copy["title"] = f(copy["title"])
    for part in copy["score_breakdown"]:
        part["reason"] = f(part["reason"])
    copy["entities"] = {k: [f(v) for v in vs] for k, vs in copy["entities"].items()}
    for alert in copy["alerts"]:
        alert["title"] = f(alert["title"])
        alert["explanation"] = f(alert["explanation"])
    for entry in copy["timeline"]["alert_entries"]:
        entry["entry"] = f(entry["entry"])
    for indicator in copy["indicators"]:
        indicator["value"] = f(indicator["value"])
    copy["limitations"] = [f(x) for x in copy["limitations"]]
    return copy


def _serialise(data: dict[str, Any]) -> str:
    # ensure_ascii=False: the leak check must see the same characters the model reads.
    return json.dumps(data, ensure_ascii=False, indent=1)


def _trim(data: dict[str, Any], step: str) -> bool:
    if step == "indicators" and len(data["indicators"]) > 5:
        data["indicators"] = data["indicators"][:5]
        return True
    if step == "alerts" and len(data["alerts"]) > 20:
        data["alerts"] = data["alerts"][:20]
        return True
    if step == "alert_timeline" and data["timeline"]["alert_entries"]:
        data["timeline"]["alert_entries"] = []
        return True
    return False


def _fields(incident: Incident) -> dict[str, Any]:
    """The allow-list: every field sent is named here."""
    events = [t for t in incident.timeline if t.alert_id is None]
    return {
        "format": FORMAT,
        "id": incident.id,
        "title": _cap(incident.title),
        "severity": incident.severity.value,
        "confidence": incident.confidence.value,
        "score": incident.score,
        "score_breakdown": [
            {"reason": _cap(c.reason), "points": c.points} for c in incident.score_breakdown
        ],
        "first_seen": incident.first_seen.isoformat(),
        "last_seen": incident.last_seen.isoformat(),
        "entities": {k: list(v) for k, v in incident.entities.items()},
        "attack": list(incident.attack),
        "alerts": [
            {
                "rule": a.detector_id,
                "kind": a.detector_kind.value,
                "title": _cap(a.title),
                "severity": a.severity.value,
                "first_seen": a.first_seen.isoformat(),
                "last_seen": a.last_seen.isoformat(),
                "events": len(a.event_ids),
                "attack": list(a.attack),
                "explanation": _cap(a.explanation) if a.explanation else None,
            }
            for a in incident.alerts
        ],
        "timeline": {
            "events": len(events),
            "first_event": events[0].timestamp.isoformat() if events else None,
            "last_event": events[-1].timestamp.isoformat() if events else None,
            "alert_entries": [
                {"time": t.timestamp.isoformat(), "entry": _cap(t.description)}
                for t in incident.timeline
                if t.alert_id is not None
            ],
        },
        "indicators": [
            {
                "type": i.type.value,
                "value": i.value,
                "enrichment": [
                    {"provider": e.provider, "data": dict(e.data) if e.data else {}}
                    for e in i.enrichment
                ],
            }
            for i in incident.indicators
        ],
        "recommended_actions": [_cap(a) for a in incident.recommended_actions],
        "limitations": [_cap(x) for x in incident.limitations],
    }
