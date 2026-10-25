"""Offline tests for scripts/verify_attack.py using a small synthetic STIX bundle."""

import hashlib
import json
from typing import Any

import pytest

from prohori.rules.attack import TACTICS, TECHNIQUES
from scripts import verify_attack


def bundle(**overrides: Any) -> dict[str, Any]:
    objects: list[dict[str, Any]] = [
        {"type": "x-mitre-tactic", "name": name, "x_mitre_shortname": tag[7:].replace("_", "-")}
        for tag, name in TACTICS.items()
    ]
    for tag, technique in TECHNIQUES.items():
        obj = {
            "type": "attack-pattern",
            "name": technique.name,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": tag[7:].upper()}
            ],
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": t[7:].replace("_", "-")}
                for t in technique.tactics
            ],
        }
        obj.update(overrides.get(tag, {}))
        objects.append(obj)
    return {"type": "bundle", "objects": objects}


def check(data: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> list[str]:
    raw = json.dumps(data).encode()
    monkeypatch.setattr(verify_attack, "ATTACK_STIX_SHA256", hashlib.sha256(raw).hexdigest())
    return verify_attack.verify(raw)


def test_matching_bundle_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    assert check(bundle(), monkeypatch) == []


def test_hash_mismatch_is_reported() -> None:
    problems = verify_attack.verify(json.dumps(bundle()).encode())
    assert any("SHA-256" in p for p in problems)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"revoked": True}, "revoked"),
        ({"x_mitre_deprecated": True}, "deprecated"),
        ({"name": "Something Else"}, "Something Else"),
        (
            {"kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "impact"}]},
            "impact",
        ),
    ],
)
def test_changed_technique_is_reported(
    override: dict[str, Any], message: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    problems = check(bundle(**{"attack.t1110": override}), monkeypatch)
    assert any(p.startswith("attack.t1110:") and message in p for p in problems), problems


def test_changed_tactics_are_reported(monkeypatch: pytest.MonkeyPatch) -> None:
    data = bundle()
    data["objects"] = [o for o in data["objects"] if o.get("x_mitre_shortname") != "stealth"]
    assert any("tactics differ" in p for p in check(data, monkeypatch))
