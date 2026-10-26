"""Print the CHANGELOG section of one version, for the GitHub release notes.

Exits with code 1 when the changelog has no section for the version, so a release cannot be
tagged without its notes.

    uv run python scripts/release_notes.py 0.1.0
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHANGELOG = ROOT / "CHANGELOG.md"


def section(changelog: str, version: str) -> str | None:
    """The body of the ``## [version]`` section, without its heading, or None."""
    heading = re.compile(rf"^## \[{re.escape(version)}\][^\n]*\n", re.MULTILINE)
    match = heading.search(changelog)
    if match is None:
        return None
    rest = changelog[match.end() :]
    end = re.search(r"^## \[|^\[[^\]]+\]: ", rest, re.MULTILINE)
    return (rest[: end.start()] if end else rest).strip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", help="version without the leading v, such as 0.1.0")
    args = parser.parse_args(argv)
    body = section(CHANGELOG.read_text(encoding="utf-8"), args.version)
    if body is None:
        print(f"CHANGELOG.md has no section for {args.version}", file=sys.stderr)
        return 1
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
