# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Check, or add, the licence header at the top of Prohori's own source files.

Every Python, SQL and Dockerfile in the repository, the report templates and the built-in rules
start with an SPDX licence identifier and the copyright line (docs/DECISIONS.md, ADR-0033).
Test data, generated output and third-party files are left alone.

    python scripts/licence_headers.py            # list files without the header (exit 1 if any)
    python scripts/licence_headers.py --fix      # add the header where it is missing
    python scripts/licence_headers.py FILE ...   # only these files (as pre-commit passes them)
"""

from __future__ import annotations

import argparse
import fnmatch
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPDX_ID = "LicenseRef-PolyForm-Strict-1.0.0"
COPYRIGHT = "Copyright (c) 2026 Utsha Basak"

#: Files that must carry the header, as repository-relative glob patterns.
INCLUDE = (
    "*.py",
    "*.sql",
    "*Dockerfile",
    "src/prohori/reports/templates/*.j2",
    "src/prohori/rules/builtin/*.yml",
)
#: Data, generated output and other people's files: never touched.
EXCLUDE = (
    "tests/fixtures/*",
    "tests/golden/*",
    "samples/*",
    "docs/examples/*",
    "data/*",
)


def comment_lines(path: str) -> tuple[str, str]:
    """The two header lines in the comment syntax of ``path``."""
    if path.endswith(".j2"):
        # A Jinja comment that also eats the newline after it, so rendered output is unchanged.
        return f"{{#- SPDX-License-Identifier: {SPDX_ID}", f"    {COPYRIGHT} -#}}"
    prefix = "--" if path.endswith(".sql") else "#"
    return f"{prefix} SPDX-License-Identifier: {SPDX_ID}", f"{prefix} {COPYRIGHT}"


def wanted(path: str) -> bool:
    """Whether ``path`` (repository-relative, forward slashes) must carry the header."""
    if any(fnmatch.fnmatch(path, pattern) for pattern in EXCLUDE):
        return False
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatch(path, p) or fnmatch.fnmatch(name, p) for p in INCLUDE)


def _first_code_line(lines: list[str], path: str) -> int:
    """Index after the lines that must stay first: a shebang, a coding cookie, parser directives."""
    index = 0
    if lines and lines[0].startswith("#!"):
        index = 1
    if (
        path.endswith(".py")
        and index < len(lines)
        and lines[index].lstrip().startswith("#")
        and "coding" in lines[index][:40]
    ):
        index += 1
    if path.endswith("Dockerfile"):
        while index < len(lines) and lines[index].lower().startswith(("# syntax=", "# escape=")):
            index += 1
    return index


def has_header(text: str, path: str) -> bool:
    """Whether the header is present within the first few lines."""
    first, second = comment_lines(path)
    head = text.splitlines()[:5]
    return first in head and second in head


def with_header(text: str, path: str) -> str:
    """``text`` with the header inserted at the right place (unchanged if already present)."""
    if has_header(text, path):
        return text
    lines = text.splitlines(keepends=True)
    index = _first_code_line(lines, path)
    first, second = comment_lines(path)
    return "".join([*lines[:index], f"{first}\n", f"{second}\n", *lines[index:]])


def tracked_files() -> list[str]:
    """Repository-relative paths of every file under version control."""
    git = "git"
    result = subprocess.run(  # noqa: S603 - fixed arguments, no shell
        [git, "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True
    )
    return [p for p in result.stdout.decode().split("\0") if p]


def missing(paths: list[str]) -> list[str]:
    """The paths among ``paths`` that should carry the header but do not."""
    out = []
    for path in paths:
        if not wanted(path):
            continue
        file = ROOT / path
        if file.is_file() and not has_header(file.read_text(encoding="utf-8"), path):
            out.append(path)
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("files", nargs="*", help="files to check (default: every tracked file)")
    parser.add_argument("--fix", action="store_true", help="add the header where it is missing")
    args = parser.parse_args(argv)
    paths = (
        [Path(f).resolve().relative_to(ROOT).as_posix() for f in args.files]
        if args.files
        else tracked_files()
    )
    bad = missing(paths)
    if args.fix:
        for path in bad:
            file = ROOT / path
            text = file.read_text(encoding="utf-8")
            file.write_text(with_header(text, path), encoding="utf-8", newline="")
            print(f"added the licence header: {path}")
    else:
        for path in bad:
            print(f"missing the licence header: {path}", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
