"""Build the ATT&CK retrieval corpus for the LLM analyst from the pinned STIX bundle.

Reads Enterprise ATT&CK (the release pinned in ``prohori.rules.attack``; about 50 MB, downloaded
unless ``--file`` is given), checks its SHA-256, and writes one JSON line per active technique and
sub-technique (neither revoked nor deprecated) to ``src/prohori/llm/data/attack.jsonl``: id, name,
tactics, and the description shortened to its first paragraph without citations or links, at
most 600 characters. Run by hand when the pinned ATT&CK release changes:

    uv run python -m scripts.build_attack_corpus [--file enterprise-attack-20.0.json]
"""

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

from prohori.rules.attack import ATTACK_STIX_SHA256, ATTACK_VERSION
from scripts.verify_attack import active, external_id, load_bundle, tag

OUT = Path(__file__).resolve().parents[1] / "src" / "prohori" / "llm" / "data" / "attack.jsonl"
MAX_DESCRIPTION = 600
NOTICE = (
    "© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission "
    "of The MITRE Corporation."
)

_CITATION = re.compile(r"\s*\(Citation:[^)]*\)")
_LINK = re.compile(r"\[([^\]]+)\]\([^)]*\)")
_CODE = re.compile(r"<code>(.*?)</code>")


def shorten(description: str) -> str:
    first = description.strip().split("\n\n", 1)[0]
    text = _CODE.sub(r"\1", _LINK.sub(r"\1", _CITATION.sub("", first)))
    text = " ".join(text.split())
    if len(text) <= MAX_DESCRIPTION:
        return text
    cut = text[:MAX_DESCRIPTION]
    end = cut.rfind(". ")
    return cut[: end + 1] if end > MAX_DESCRIPTION // 2 else cut.rstrip() + "…"


def build(data: bytes) -> list[dict[str, Any]]:
    digest = hashlib.sha256(data).hexdigest()
    if digest != ATTACK_STIX_SHA256:
        raise SystemExit(f"SHA-256 {digest} does not match the pinned {ATTACK_STIX_SHA256}")
    entries = []
    for obj in json.loads(data.decode("utf-8"))["objects"]:
        if obj.get("type") != "attack-pattern" or not active(obj):
            continue
        technique = external_id(obj)
        if technique is None:
            continue
        tactics = sorted(
            tag(p["phase_name"])
            for p in obj.get("kill_chain_phases", [])
            if p.get("kill_chain_name") == "mitre-attack"
        )
        entries.append(
            {
                "id": technique,
                "name": obj["name"],
                "tactics": tactics,
                "description": shorten(obj.get("description", "")),
            }
        )
    return sorted(entries, key=lambda e: e["id"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--file", type=Path, help="a local copy of the pinned bundle")
    args = parser.parse_args(argv)
    entries = build(load_bundle(args.file))
    header = {"notice": NOTICE, "attack_version": ATTACK_VERSION, "techniques": len(entries)}
    lines = [json.dumps(header, ensure_ascii=False)]
    lines += [json.dumps(e, ensure_ascii=False) for e in entries]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    sys.stdout.write(f"wrote {OUT} ({len(entries)} techniques)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
