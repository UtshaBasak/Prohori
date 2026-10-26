"""Shared incidents for the report tests: the committed sample and a hostile one."""

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from prohori.schema import Incident

ROOT = Path(__file__).resolve().parents[3]
SAMPLE_DIR = ROOT / "samples" / "incidents"

#: Payloads that must be inert in every report format.
SCRIPT = "<script>alert(1)</script>"
LINK = "[click](javascript:alert(1))"
FORMULA = '=HYPERLINK("http://evil.example/x","open")'
ANSI = "\x1b[31mred\x1b[0m"
HEADING = "line one\n# injected heading"
PIPE = "a | b | c"
URL = "see http://evil.example and www.evil.example"
HOSTILE = f"{SCRIPT} {LINK} {ANSI} {HEADING} {PIPE} {URL}"


@pytest.fixture
def sample_path() -> Path:
    (path,) = SAMPLE_DIR.glob("INC-*.json")
    return path


@pytest.fixture
def sample(sample_path: Path) -> Incident:
    return Incident.model_validate_json(sample_path.read_text(encoding="utf-8"))


@pytest.fixture
def hostile() -> Incident:
    """An incident with attacker-controlled text in every free-text field."""
    when = datetime(2026, 10, 24, 21, 0, tzinfo=UTC)
    alert = {
        "detector_id": "PRH-AUTH-001",
        "title": f"Title {HOSTILE}",
        "severity": "high",
        "event_ids": ["evt-1"],
        "entities": {"source.ip": "203.0.113.7", "user.name": FORMULA},
        "first_seen": when,
        "last_seen": when,
        "attack": ["attack.t1110"],
        "explanation": f"Explanation {HOSTILE}",
    }
    data = {
        "id": "INC-0123456789abcdef",
        "title": f"Incident {HOSTILE}",
        "severity": "high",
        "score": 35,
        "score_breakdown": [{"reason": f"Reason {HOSTILE}", "points": 35}],
        "first_seen": when,
        "last_seen": when,
        "entities": {"source.ip": ["203.0.113.7"], "user.name": [FORMULA]},
        "alerts": [alert],
        "timeline": [
            {
                "timestamp": when,
                "description": FORMULA,
                "event_id": "evt-1",
                "account": FORMULA,
                "source_ip": "203.0.113.7",
            },
            {"timestamp": when, "description": f"Event {HOSTILE}", "event_id": "evt-2"},
        ],
        "indicators": [
            {
                "type": "ip",
                "value": "203.0.113.7",
                "enrichment": [
                    {
                        "provider": "abuseipdb",
                        "retrieved_at": when,
                        "data": {"as_org": f"Org {HOSTILE}", "city": SCRIPT},
                        "note": f"Note {HOSTILE}",
                    }
                ],
            },
            {"type": "user_agent", "value": f"UA {HOSTILE}"},
        ],
        "attack": ["attack.t1110"],
        "recommended_actions": [f"Action {HOSTILE}", "1. numbered"],
        "limitations": [f"Limitation {HOSTILE}"],
    }
    return Incident.model_validate_json(json.dumps(data, default=str))
