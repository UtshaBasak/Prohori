"""Report rendering: golden files, injection resistance and self-contained HTML."""

import csv
import io
import json
import os
import re
from pathlib import Path

import pytest

from prohori.reports import (
    RedactionNote,
    Redactor,
    ReportFormat,
    ReportSource,
    clean,
    csv_cell,
    md_escape,
    render,
)
from prohori.reports.render import REPORT_FORMAT, md_code
from prohori.schema import Incident
from prohori.version import __version__
from tests.unit.reports.conftest import FORMULA, ROOT

GOLDEN = ROOT / "tests" / "golden" / "reports"
#: Set PROHORI_UPDATE_GOLDEN=1 to rewrite the golden files after an intended output change.
UPDATE_GOLDEN = os.environ.get("PROHORI_UPDATE_GOLDEN") == "1"
SOURCE = ReportSource(name="INC-sample.json", sha256="0" * 64)
KEY = b"golden-test-key-not-secret-0001"


def _golden(name: str, text: str) -> None:
    text = text.replace(__version__, "<version>")
    path = GOLDEN / name
    if UPDATE_GOLDEN:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    assert text == path.read_text(encoding="utf-8")


@pytest.mark.parametrize("fmt", list(ReportFormat))
def test_sample_matches_golden_file(sample: Incident, fmt: ReportFormat) -> None:
    _golden(f"takeover.{fmt.value}", render(sample, fmt, source=SOURCE))


def test_redacted_sample_matches_golden_file(sample: Incident) -> None:
    redactor = Redactor(KEY, ips=True)
    redacted = redactor.redact(sample)
    note = RedactionNote(users=True, ips=True, replaced=len(redactor.replaced))
    _golden("takeover-redacted.md", render(redacted, ReportFormat.MARKDOWN, redaction=note))


def test_markdown_has_every_section(sample: Incident) -> None:
    text = render(sample, ReportFormat.MARKDOWN)
    for heading in (
        "## Summary",
        "## Timeline",
        "## Indicators",
        "## Affected entities",
        "## Evidence",
        "## ATT&CK mapping",
        "## Score breakdown",
        "## Recommended actions",
        "## Confidence and limitations",
        "## Appendix",
        "### Rules fired",
        "### Inputs",
        "### Versions",
    ):
        assert f"\n{heading}\n" in text, heading
    assert "Enterprise ATT&CK v20.0" in text
    assert "| **100** | **Total** |" in text


def test_output_is_deterministic(sample: Incident) -> None:
    for fmt in ReportFormat:
        assert render(sample, fmt) == render(sample, fmt)


# ---------------------------------------------------------------- injection


def _all_formats(incident: Incident) -> dict[ReportFormat, str]:
    return {fmt: render(incident, fmt) for fmt in ReportFormat}


def test_no_terminal_escapes_in_any_format(hostile: Incident) -> None:
    for fmt, text in _all_formats(hostile).items():
        assert "\x1b" not in text, fmt
        assert "\\u001b" not in text, fmt


def test_html_escapes_everything(hostile: Incident) -> None:
    text = render(hostile, ReportFormat.HTML)
    assert "<script" not in text
    assert "&lt;script&gt;" in text
    assert "javascript:" not in re.sub(r">[^<]*<", "><", text)  # never inside a tag
    assert not re.search(r"\b(?:src|href|action)\s*=", text)  # no links or external resources
    assert "Content-Security-Policy" in text
    assert "default-src 'none'" in text
    assert "<a " not in text


def test_markdown_neutralises_links_html_and_tables(hostile: Incident) -> None:
    text = render(hostile, ReportFormat.MARKDOWN)
    prose = re.sub(r"(`+).*?\1", "", text)  # code spans show their content literally
    assert not re.search(r"(?<!\\)<script", prose)
    assert not re.search(r"(?<!\\)\[click(?<!\\)\]", prose)
    assert "http://evil" not in prose  # bare URLs would be autolinked
    assert "www.evil" not in prose
    assert "\n# injected heading" not in text  # newlines are collapsed
    # Every table row keeps its column count: pipes from the data are escaped.
    timeline = [ln for ln in text.splitlines() if ln.startswith("| 2026-10-24")]
    assert all(len(re.split(r"(?<!\\)\|", ln)) == 5 for ln in timeline)
    assert "1\\. numbered" in text


def test_csv_cells_cannot_be_formulas(hostile: Incident) -> None:
    rows = list(csv.reader(io.StringIO(render(hostile, ReportFormat.CSV))))
    assert rows[0][0] == "timestamp"
    for row in rows[1:]:
        for cell in row:
            assert not cell.startswith(("=", "+", "-", "@")), cell
    assert rows[1][2] == "'" + FORMULA
    assert rows[1][5] == "'" + FORMULA


def test_json_report_is_structured_and_clean(hostile: Incident) -> None:
    document = json.loads(render(hostile, ReportFormat.JSON))
    assert document["format"] == REPORT_FORMAT
    assert document["attack"]["version"] == "20.0"
    assert document["incident"]["id"] == hostile.id
    assert "\n" not in document["incident"]["title"]


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("=1+1", "'=1+1"),
        ("+cmd", "'+cmd"),
        ("-2", "'-2"),
        ("@SUM(A1)", "'@SUM(A1)"),
        (chr(0xFF1D) + "1", "'" + chr(0xFF1D) + "1"),  # full-width equals sign
        ("plain", "plain"),
        (None, ""),
    ],
)
def test_csv_cell(value: str | None, expected: str) -> None:
    assert csv_cell(value) == expected


def test_clean_caps_and_flattens() -> None:
    assert clean("a\n\tb\x00c") == "a bc"
    assert clean("x" * 600) == "x" * 499 + "…"
    assert clean(None) == ""


def test_md_escape_and_code() -> None:
    assert md_escape("*bold* _x_ <b> [a](b) | ~ & @ $") == (
        "\\*bold\\* \\_x\\_ \\<b\\> \\[a\\](b) \\| \\~ \\& \\@ \\$"
    )
    assert md_code("a`b|c") == "``a`b\\|c``"
    assert md_code("`x`") == "`` `x` ``"


def test_report_without_provenance_or_enrichment(hostile: Incident) -> None:
    text = render(hostile, ReportFormat.MARKDOWN)
    assert "Not recorded." in text
    assert "Incident built with: unknown" in text
    assert "Not redacted" in text


def test_templates_are_packaged() -> None:
    templates = Path(__file__).resolve().parents[3] / "src" / "prohori" / "reports" / "templates"
    assert {p.name for p in templates.iterdir()} >= {"report.md.j2", "report.html.j2"}
