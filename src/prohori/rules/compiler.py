"""Turn a rule document into a validated, compiled rule.

Every problem is reported as a :class:`RuleError` with its path in the document, so the loader can
point at the exact line.
"""

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC
from typing import Any, TypeVar
from zoneinfo import ZoneInfo

from pydantic import BaseModel, ValidationError

from prohori.rules.condition import (
    NAME_PATTERN,
    SPECIAL_BLOCKS,
    ConditionError,
    Node,
    evaluate,
    parse_condition,
    references,
    split_special,
)
from prohori.rules.matching import Path, RuleError, Selection, compile_selection
from prohori.rules.model import AggregateSpec, RuleMeta, SequenceSpec
from prohori.schema import Event

M = TypeVar("M", bound=BaseModel)

_NAME_RE = re.compile(rf"^{NAME_PATTERN}$")
_RESERVED = frozenset({"condition", *SPECIAL_BLOCKS})
_KEYWORDS = frozenset({"and", "or", "not", "of", "them", "any", "all"})


@dataclass(frozen=True)
class CompiledRule:
    """A validated rule with compiled selections.

    ``filter`` is the stateless part of the condition. For a plain rule it decides alone whether an
    event raises an alert; for aggregate and sequence rules it selects the candidate events that
    the stateful engine counts.
    """

    meta: RuleMeta
    selections: Mapping[str, Selection]
    condition: Node
    filter: Node | None
    aggregate: AggregateSpec | None = None
    sequence: SequenceSpec | None = None
    source: str = field(default="", compare=False)

    @property
    def id(self) -> str:
        return self.meta.id

    @property
    def is_stateful(self) -> bool:
        return self.aggregate is not None or self.sequence is not None

    def matches_logsource(self, event: Event) -> bool:
        logsource = self.meta.logsource
        if logsource.category is not None and event.event.category is not logsource.category:
            return False
        return logsource.log_source is None or (
            event.log_source.casefold() == logsource.log_source.casefold()
        )

    def selection_matches(self, name: str, event: Event) -> bool:
        return self.selections[name].matches(event)

    def matches_filter(self, event: Event) -> bool:
        """Whether ``event`` passes the log source and the stateless part of the condition.

        For a sequence rule (whose condition is only ``sequence``), an event passes if it matches
        any step's selection.
        """
        if not self.matches_logsource(event):
            return False
        if self.filter is not None:
            return evaluate(self.filter, lambda name: self.selection_matches(name, event))
        if self.sequence is not None:
            return any(self.selection_matches(s.selection, event) for s in self.sequence.steps)
        return False  # pragma: no cover - compile_rule guarantees a filter or a sequence


@dataclass
class CompileResult:
    """Outcome of :func:`compile_rule`: a rule, or the errors that prevented it."""

    rule: CompiledRule | None
    errors: list[RuleError]


def _pydantic_errors(exc: ValidationError, prefix: Path = ()) -> list[RuleError]:
    return [
        RuleError((*prefix, *error["loc"]), error["msg"].removeprefix("Value error, "))
        for error in exc.errors()
    ]


def _model(cls: type[M], raw: object, path: Path, errors: list[RuleError]) -> M | None:
    try:
        return cls.model_validate(raw)
    except ValidationError as exc:
        errors.extend(_pydantic_errors(exc, path))
        return None


def compile_rule(document: object, source: str = "") -> CompileResult:
    """Validate and compile a rule document (the parsed YAML mapping)."""
    errors: list[RuleError] = []
    if not isinstance(document, Mapping):
        return CompileResult(None, [RuleError((), "a rule must be a YAML mapping")])
    meta = _model(RuleMeta, document, (), errors)
    detection = document.get("detection")
    if not isinstance(detection, Mapping):
        if meta is not None:  # pydantic already reported a missing/invalid detection otherwise
            errors.append(RuleError(("detection",), "detection must be a mapping"))
        return CompileResult(None, errors)

    tz = ZoneInfo(meta.timezone) if meta is not None else UTC
    selections: dict[str, Selection] = {}
    for name, raw in detection.items():
        key = str(name)
        path: Path = ("detection", key)
        if key in _RESERVED:
            continue
        if not _NAME_RE.match(key) or key.lower() in _KEYWORDS:
            errors.append(RuleError(path, f"invalid selection name {key!r}"))
            continue
        selection = compile_selection(key, raw, path, errors, tz)
        if selection is not None:
            selections[key] = selection
    if not selections and not any(e.path[:1] == ("detection",) for e in errors):
        errors.append(RuleError(("detection",), "define at least one selection"))

    aggregate = None
    if "aggregate" in detection:
        aggregate = _model(
            AggregateSpec, detection["aggregate"], ("detection", "aggregate"), errors
        )
    sequence = None
    if "sequence" in detection:
        sequence = _model(SequenceSpec, detection["sequence"], ("detection", "sequence"), errors)
    if aggregate is not None and sequence is not None:
        errors.append(RuleError(("detection",), "use either aggregate or sequence, not both"))

    defined = {str(name) for name in detection if str(name) not in _RESERVED}
    condition, filter_node = _compile_condition(detection, defined, errors)

    if condition is not None:
        used = references(condition)
        if aggregate is not None and aggregate.ratio is not None:
            used.add(aggregate.ratio.selection)
            if aggregate.ratio.selection not in defined:
                errors.append(
                    RuleError(
                        ("detection", "aggregate", "ratio", "selection"),
                        f"unknown selection {aggregate.ratio.selection!r}",
                    )
                )
        if sequence is not None:
            for index, step in enumerate(sequence.steps):
                used.add(step.selection)
                if step.selection not in defined:
                    errors.append(
                        RuleError(
                            ("detection", "sequence", "steps", index, "selection"),
                            f"unknown selection {step.selection!r}",
                        )
                    )
        for name in sorted(defined - used):
            errors.append(RuleError(("detection", name), f"selection {name!r} is never used"))
        for block, spec in (("aggregate", aggregate), ("sequence", sequence)):
            if block in detection and block not in used and spec is not None:
                errors.append(
                    RuleError(
                        ("detection", block), f"'{block}' is defined but not in the condition"
                    )
                )

    if errors or meta is None or condition is None:
        return CompileResult(None, errors)
    rule = CompiledRule(
        meta=meta,
        selections=selections,
        condition=condition,
        filter=filter_node,
        aggregate=aggregate,
        sequence=sequence,
        source=source,
    )
    return CompileResult(rule, [])


def _compile_condition(
    detection: Mapping[Any, Any], defined: set[str], errors: list[RuleError]
) -> tuple[Node | None, Node | None]:
    path: Path = ("detection", "condition")
    raw = detection.get("condition")
    if raw is None:
        errors.append(RuleError(("detection",), "missing condition"))
        return None, None
    try:
        condition = parse_condition(raw, defined)
        filter_node, specials = split_special(condition)
    except ConditionError as exc:
        errors.append(RuleError(path, str(exc)))
        return None, None
    for name in sorted(references(condition)):
        if name in SPECIAL_BLOCKS:
            if name not in detection:
                errors.append(RuleError(path, f"'{name}' is used but not defined"))
        elif name not in defined:
            errors.append(RuleError(path, f"unknown selection {name!r}"))
    if "sequence" in specials and filter_node is not None:
        errors.append(RuleError(path, "a sequence rule's condition must be just 'sequence'"))
    if "aggregate" in specials and filter_node is None:
        errors.append(
            RuleError(path, "'aggregate' needs a selection to count, e.g. 'x and aggregate'")
        )
    return condition, filter_node
