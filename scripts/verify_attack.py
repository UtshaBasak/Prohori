"""Check prohori.rules.attack against the pinned official ATT&CK STIX bundle.

Downloads the bundle named by ``ATTACK_STIX_URL`` (about 50 MB), checks its SHA-256, and confirms
that every listed tactic exists and every listed technique has the recorded name and tactics and
is neither revoked nor deprecated. Run by hand when changing the ATT&CK list or version:

    uv run python scripts/verify_attack.py [--file enterprise-attack-20.0.json]
"""

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

from prohori.rules.attack import ATTACK_STIX_SHA256, ATTACK_STIX_URL, TACTICS, TECHNIQUES


def load_bundle(path: Path | None) -> bytes:
    if path is not None:
        return path.read_bytes()
    with urllib.request.urlopen(ATTACK_STIX_URL, timeout=120) as response:  # noqa: S310 - fixed https URL
        data: bytes = response.read()
    return data


def active(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def external_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return str(ref["external_id"])
    return None


def tag(shortname: str) -> str:
    return "attack." + shortname.lower().replace("-", "_")


def verify(data: bytes) -> list[str]:
    problems: list[str] = []
    digest = hashlib.sha256(data).hexdigest()
    if digest != ATTACK_STIX_SHA256:
        problems.append(f"SHA-256 {digest} does not match the pinned {ATTACK_STIX_SHA256}")
    objects = json.loads(data.decode("utf-8"))["objects"]

    tactics = {
        tag(o["x_mitre_shortname"]): o["name"]
        for o in objects
        if o["type"] == "x-mitre-tactic" and active(o)
    }
    if tactics != TACTICS:
        problems.append(f"tactics differ: bundle has {sorted(tactics.items())}")

    techniques = {}
    for o in objects:
        ext = external_id(o) if o["type"] == "attack-pattern" else None
        if ext:
            techniques[tag(ext)] = o
    for key, expected in TECHNIQUES.items():
        obj = techniques.get(key)
        if obj is None or not active(obj):
            problems.append(f"{key}: missing, revoked or deprecated")
            continue
        phases = tuple(
            tag(p["phase_name"])
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        )
        if obj["name"] != expected.name or set(phases) != set(expected.tactics):
            problems.append(f"{key}: bundle has {obj['name']!r} {phases}, list has {expected}")
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--file", type=Path, help="use a downloaded bundle instead of fetching it")
    args = parser.parse_args()
    problems = verify(load_bundle(args.file))
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print(f"All {len(TACTICS)} tactics and {len(TECHNIQUES)} techniques verified.")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
