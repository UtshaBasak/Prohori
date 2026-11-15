# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Licence checks: Prohori's own files carry the header, and no runtime dependency has a licence
that would stop Prohori being distributed under its own terms (ADR-0033)."""

from __future__ import annotations

import re
import shutil
import tomllib
from importlib import metadata

import pytest

from prohori.version import __license__
from scripts.licence_headers import (
    ROOT,
    SPDX_ID,
    comment_lines,
    has_header,
    missing,
    tracked_files,
    wanted,
    with_header,
)

# --------------------------------------------------------------------------- licence text


def test_licence_file_is_polyform_strict_with_the_required_notice() -> None:
    text = (ROOT / "LICENSE").read_text(encoding="utf-8")
    assert text.startswith("Required Notice: Copyright (c) 2026 Utsha Basak")
    assert "# PolyForm Strict License 1.0.0" in text
    assert "<https://polyformproject.org/licenses/strict/1.0.0>" in text
    assert (
        (ROOT / "docs/legal/MIT-LICENSE-up-to-1.0.1.txt")
        .read_text(encoding="utf-8")
        .startswith("MIT License")
    )


def test_package_metadata_names_the_same_licence() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["license"] == __license__ == SPDX_ID
    assert project["license-files"] == ["LICENSE"]


# --------------------------------------------------------------------------- headers


@pytest.mark.skipif(
    shutil.which("git") is None or not (ROOT / ".git").exists(), reason="needs a git checkout"
)
def test_every_own_source_file_has_the_licence_header() -> None:
    files = tracked_files()
    assert any(f.endswith(".py") for f in files)
    assert missing(files) == [], "run: python scripts/licence_headers.py --fix"


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("src/prohori/cli/app.py", True),
        ("pipeline/Dockerfile", True),
        ("pipeline/dbt/models/marts/fct_alerts.sql", True),
        ("src/prohori/reports/templates/report.md.j2", True),
        ("src/prohori/rules/builtin/brute-force.yml", True),
        ("tests/fixtures/rules/valid.yml", False),
        ("tests/golden/report.md", False),
        ("samples/logs/auth.log", False),
        ("README.md", False),
        (".github/workflows/ci.yml", False),
    ],
)
def test_which_files_need_the_header(path: str, expected: bool) -> None:
    assert wanted(path) is expected


def test_header_goes_after_a_shebang_and_dockerfile_directives() -> None:
    script = with_header("#!/usr/bin/env python\nprint('hi')\n", "tool.py")
    assert script.splitlines()[0] == "#!/usr/bin/env python"
    assert script.splitlines()[1] == f"# SPDX-License-Identifier: {SPDX_ID}"

    docker = with_header("# syntax=docker/dockerfile:1\nFROM scratch\n", "Dockerfile")
    assert docker.splitlines()[0] == "# syntax=docker/dockerfile:1"
    assert has_header(docker, "Dockerfile")


def test_header_is_added_once() -> None:
    once = with_header("SELECT 1\n", "model.sql")
    assert once.startswith("-- SPDX-License-Identifier:")
    assert with_header(once, "model.sql") == once


def test_template_header_leaves_rendered_output_unchanged() -> None:
    jinja2 = pytest.importorskip("jinja2")
    source = "# {{ title }}\n"
    template = with_header(source, "report.md.j2")
    assert comment_lines("report.md.j2")[0] in template
    render = jinja2.Environment(autoescape=False).from_string
    assert render(template).render(title="T") == render(source).render(title="T")


# --------------------------------------------------------------------------- dependencies

#: Licence words that would stop Prohori being distributed under its own terms, or limit it to
#: non-commercial use. LGPL (a separate, replaceable library) is fine.
_FORBIDDEN = re.compile(
    r"affero|\bagpl|\bsspl|server side public|commons clause|non-?commercial|"
    r"\bgpl|general public licen[cs]e",
    re.IGNORECASE,
)
_ALLOWED_COPYLEFT = re.compile(r"lgpl|lesser|library general public", re.IGNORECASE)
#: Dual-licensed packages with a permissive choice, and why they are fine.
_DUAL_LICENSED = {
    "text-unidecode": "Artistic License or GPL; the Artistic License applies",
}


def _name(requirement: str) -> str:
    return re.split(r"[\s;\[<>=!~(]", requirement, maxsplit=1)[0].lower().replace("_", "-")


def _runtime_closure() -> set[str]:
    """Every installed distribution reachable from Prohori's requirements and its extras."""
    seen: set[str] = set()
    todo = ["prohori"]
    while todo:
        name = todo.pop()
        if name in seen:
            continue
        try:
            dist = metadata.distribution(name)
        except metadata.PackageNotFoundError:
            continue  # an extra that is not installed in this environment
        seen.add(name)
        # Prohori's own extras are all followed; a dependency's optional extras are not installed
        # with Prohori, so they are skipped.
        todo.extend(
            _name(r)
            for r in dist.requires or []
            if name == "prohori" or "extra ==" not in r.replace("extra==", "extra ==")
        )
    seen.discard("prohori")
    return seen


def _licence_texts(name: str) -> list[str]:
    meta = metadata.metadata(name)
    texts = [(meta.get_all("License-Expression") or [""])[0]]
    licence = (meta.get_all("License") or [""])[0]
    if len(licence) < 200:  # a short name, not a whole licence text pasted into the field
        texts.append(licence)
    texts += [c for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    return [t for t in texts if t]


def _forbidden(text: str) -> bool:
    if " OR " in text:  # an SPDX choice: fine if any alternative is fine
        return all(_forbidden(part) for part in text.split(" OR "))
    return bool(_FORBIDDEN.search(text)) and not _ALLOWED_COPYLEFT.search(text)


def test_no_runtime_dependency_has_a_strong_copyleft_or_non_commercial_licence() -> None:
    closure = _runtime_closure()
    assert "pydantic" in closure  # the walk works
    bad = {
        name: texts
        for name in sorted(closure)
        if name not in _DUAL_LICENSED
        and (texts := _licence_texts(name))
        and any(_forbidden(t) for t in texts)
        and not any(t for t in texts if not _forbidden(t) and "OSI Approved" not in t)
    }
    assert bad == {}


@pytest.mark.parametrize(
    ("text", "forbidden"),
    [
        ("MIT", False),
        ("LGPL-3.0-only", False),
        ("License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)", False),
        ("GPL-3.0-or-later", True),
        ("AGPL-3.0-only", True),
        ("MIT OR GPL-2.0-only", False),
        ("License :: OSI Approved :: GNU General Public License v2 (GPLv2)", True),
        ("PolyForm-Noncommercial-1.0.0", True),
    ],
)
def test_licence_classification(text: str, forbidden: bool) -> None:
    assert _forbidden(text) is forbidden
