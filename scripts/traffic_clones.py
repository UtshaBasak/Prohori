"""Keep an all-time count of git clones for the README badge.

GitHub shows clone numbers for the last 14 days only. Each run folds the latest 14 days into a
per-day record that never forgets, and writes a shields.io endpoint badge with the total. A day
still inside the window is overwritten, since GitHub may still be counting it; once it leaves the
window, its last count stays.

Run by ``.github/workflows/traffic.yml``; standard library only, so the workflow needs no
installation step:

    python scripts/traffic_clones.py <api-response.json> <data-dir>

``<api-response.json>`` is the body of ``GET /repos/{owner}/{repo}/traffic/clones``; ``<data-dir>``
holds ``clones.json`` (the record) and ``clones-badge.json`` (the badge).
"""

import json
import sys
from pathlib import Path
from typing import Any

RECORD = "clones.json"
BADGE = "clones-badge.json"


def merge(record: dict[str, Any], response: dict[str, Any]) -> dict[str, Any]:
    """Fold a traffic/clones response into the record and recompute the totals."""
    clones = response.get("clones")
    if not isinstance(clones, list):
        msg = f"not a traffic/clones response: {json.dumps(response)[:200]}"
        raise ValueError(msg)
    days: dict[str, dict[str, int]] = dict(record.get("days", {}))
    for day in clones:
        days[str(day["timestamp"])[:10]] = {
            "count": int(day["count"]),
            "uniques": int(day["uniques"]),
        }
    ordered = dict(sorted(days.items()))  # by date, so the file reads as a diary
    return {
        "days": ordered,
        "total": sum(d["count"] for d in ordered.values()),
        "since": next(iter(ordered), None),
    }


def badge(total: int) -> dict[str, Any]:
    return {"schemaVersion": 1, "label": "clones", "message": f"{total:,}", "color": "blue"}


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2:
        print("usage: traffic_clones.py <api-response.json> <data-dir>", file=sys.stderr)
        return 2
    response_path, data_dir = Path(args[0]), Path(args[1])
    record_path = data_dir / RECORD
    record = json.loads(record_path.read_text(encoding="utf-8")) if record_path.is_file() else {}
    try:
        record = merge(record, json.loads(response_path.read_text(encoding="utf-8")))
    except (ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    data_dir.mkdir(parents=True, exist_ok=True)
    record_path.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    (data_dir / BADGE).write_text(
        json.dumps(badge(record["total"])) + "\n", encoding="utf-8", newline="\n"
    )
    print(f"{record['total']} clones since {record['since']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
