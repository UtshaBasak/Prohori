"""Tests for the condition parser and evaluator."""

import contextlib
import re

import pytest
from hypothesis import given
from hypothesis import strategies as st

from prohori.rules.condition import (
    MAX_CONDITION_LENGTH,
    MAX_DEPTH,
    And,
    ConditionError,
    Not,
    Or,
    Quantifier,
    Ref,
    evaluate,
    parse_condition,
    references,
    split_special,
)

SELECTIONS = ["selection", "filter", "probe_a", "probe_b", "other"]


def parse(text: str) -> object:
    return parse_condition(text, SELECTIONS)


class TestParsing:
    def test_single_name(self) -> None:
        assert parse("selection") == Ref("selection")

    def test_precedence_not_and_or(self) -> None:
        assert parse("selection or not filter and other") == Or(
            (Ref("selection"), And((Not(Ref("filter")), Ref("other"))))
        )

    def test_parentheses(self) -> None:
        assert parse("(selection or filter) and other") == And(
            (Or((Ref("selection"), Ref("filter"))), Ref("other"))
        )

    def test_keywords_case_insensitive(self) -> None:
        assert parse("selection AND NOT filter") == And((Ref("selection"), Not(Ref("filter"))))

    def test_quantifiers(self) -> None:
        assert parse("1 of probe_*") == Quantifier(False, ("probe_a", "probe_b"))
        assert parse("any of probe_*") == Quantifier(False, ("probe_a", "probe_b"))
        assert parse("all of them") == Quantifier(True, tuple(sorted(SELECTIONS)))

    def test_whitespace_and_newlines(self) -> None:
        assert parse("  selection\n  and\tnot filter ") == And(
            (Ref("selection"), Not(Ref("filter")))
        )

    @pytest.mark.parametrize(
        ("text", "message"),
        [
            ("", "non-empty"),
            ("   ", "non-empty"),
            ("selection and", "unexpected end"),
            ("selection filter", "after the end"),
            ("(selection", "expected ')'"),
            ("selection)", "after the end"),
            (")", "unexpected ')'"),
            ("and selection", "unexpected 'and'"),
            ("selection && filter", "unexpected token"),
            ("1 of nothing_*", "no selection matches"),
            ("1 of selection", "pattern ending in"),
            ("1", "unexpected '1'"),
            ("probe_*", "unexpected 'probe_*'"),
            ("x" * (MAX_CONDITION_LENGTH + 1), "longer than"),
            ("not " * (MAX_DEPTH + 2) + "selection", "deeper than"),
            ("(" * (MAX_DEPTH + 2) + "selection" + ")" * (MAX_DEPTH + 2), "deeper than"),
        ],
    )
    def test_errors(self, text: str, message: str) -> None:
        with pytest.raises(ConditionError, match=re.escape(message)):
            parse(text)

    def test_quantifier_without_selections(self) -> None:
        with pytest.raises(ConditionError, match="no selections"):
            parse_condition("1 of them", [])

    @given(st.text(max_size=80))
    def test_arbitrary_text_parses_or_raises_condition_error(self, text: str) -> None:
        with contextlib.suppress(ConditionError):
            parse(text)

    @given(
        st.lists(
            st.sampled_from(
                ["selection", "filter", "and", "or", "not", "(", ")", "1", "of", "them"]
            ),
            max_size=20,
        )
    )
    def test_token_soup_parses_or_raises_condition_error(self, tokens: list[str]) -> None:
        with contextlib.suppress(ConditionError):
            parse(" ".join(tokens))


class TestEvaluation:
    @pytest.mark.parametrize(
        ("text", "true_names", "expected"),
        [
            ("selection and not filter", {"selection"}, True),
            ("selection and not filter", {"selection", "filter"}, False),
            ("selection or filter", set(), False),
            ("1 of probe_*", {"probe_b"}, True),
            ("all of probe_*", {"probe_b"}, False),
            ("all of probe_*", {"probe_a", "probe_b"}, True),
            ("not (selection or filter)", set(), True),
        ],
    )
    def test_truth_table(self, text: str, true_names: set[str], expected: bool) -> None:
        assert evaluate(parse(text), lambda name: name in true_names) is expected  # type: ignore[arg-type]

    def test_references(self) -> None:
        node = parse_condition("selection and not 1 of probe_*", SELECTIONS)
        assert references(node) == {"selection", "probe_a", "probe_b"}


class TestSplitSpecial:
    def test_aggregate_as_top_level_term(self) -> None:
        node = parse_condition("selection and not filter and aggregate", SELECTIONS)
        filter_node, specials = split_special(node)
        assert specials == {"aggregate"}
        assert filter_node == And((Ref("selection"), Not(Ref("filter"))))

    def test_only_special(self) -> None:
        filter_node, specials = split_special(parse_condition("sequence", SELECTIONS))
        assert (filter_node, specials) == (None, {"sequence"})

    @pytest.mark.parametrize(
        "text",
        [
            "selection or aggregate",
            "not aggregate and selection",
            "selection and (filter or sequence)",
        ],
    )
    def test_nested_special_rejected(self, text: str) -> None:
        with pytest.raises(ConditionError, match="top-level"):
            split_special(parse_condition(text, SELECTIONS))
