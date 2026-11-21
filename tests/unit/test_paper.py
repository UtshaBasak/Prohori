# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""The cross-dataset paper: generated from results/, with no number typed by hand."""

import re

from scripts import build_paper

TEMPLATE = build_paper.TEMPLATE.read_text(encoding="utf-8")


def _prose(text: str) -> str:
    """The template without its code blocks, its reference list and the licence's version."""
    body = text.split("\n## References", 1)[0]
    body = re.sub(r"```.*?```", "", body, flags=re.DOTALL)
    return body.replace("PolyForm Strict License 1.0.0", "PolyForm Strict License")


def test_the_committed_paper_and_figures_match_the_results() -> None:
    assert build_paper.main(["--check"]) == 0


def test_no_result_is_typed_into_the_template() -> None:
    prose = _prose(TEMPLATE)
    assert not re.findall(r"\d\.\d", prose), "decimals must come from placeholders"
    assert not re.findall(r"\d\s?%", prose), "percentages must come from placeholders"


def test_every_placeholder_has_a_value() -> None:
    data = build_paper.values()
    data.update(build_paper.tables(data))
    used = set(build_paper.PLACEHOLDER.findall(TEMPLATE))
    assert used
    assert used <= set(data)


def test_every_reference_is_cited_and_every_citation_listed() -> None:
    body, references = TEMPLATE.split("\n## References", 1)
    listed = {int(n) for n in re.findall(r"^(\d+)\. ", references, flags=re.MULTILINE)}
    cited = {
        int(n) for group in re.findall(r"\[(\d+(?:, \d+)*)\]", body) for n in group.split(", ")
    }
    assert listed == set(range(1, len(listed) + 1))
    assert cited == listed


def test_figures_are_svg_with_titles() -> None:
    for name in ("fig1-roc-auc-difference.svg", "fig2-few-shot.svg"):
        svg = (build_paper.FIGURES / name).read_text(encoding="utf-8")
        assert svg.startswith("<svg ")
        assert "<title>" in svg
