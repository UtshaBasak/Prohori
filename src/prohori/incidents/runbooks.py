"""Recommended actions from the rules' Markdown runbooks.

A rule's ``response`` names its runbook. Built-in runbooks are packaged with Prohori; for other
rules the path is relative to the directory of the rule file. The bullets under the
``## Recommended actions`` heading become the incident's recommended actions.
"""

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from prohori.rules import CompiledRule, builtin_rules_dir, builtin_runbook_path

#: Largest runbook read, in bytes; the rest of a longer file is ignored.
MAX_RUNBOOK_BYTES = 64 * 1024
#: Most actions taken from one runbook.
MAX_ACTIONS_PER_RUNBOOK = 20

_HEADING = re.compile(r"^#{1,6}\s+(?P<title>.+?)\s*#*\s*$")
_BULLET = re.compile(r"^(?:[-*+]|\d{1,3}[.)])\s+(?P<text>.*)$")


@dataclass(frozen=True)
class RuleGuidance:
    """What the incident builder takes from a rule besides its alerts."""

    rule_id: str
    actions: tuple[str, ...] = ()
    false_positives: tuple[str, ...] = ()


def extract_actions(markdown: str) -> tuple[str, ...]:
    """Return the bullets under ``## Recommended actions``, wrapped lines joined."""
    actions: list[str] = []
    in_section = False
    for line in markdown.splitlines():
        heading = _HEADING.match(line)
        if heading:
            in_section = heading["title"].strip().lower() == "recommended actions"
            continue
        if not in_section:
            continue
        bullet = _BULLET.match(line)
        if bullet:
            actions.append(bullet["text"].strip())
        elif line.startswith((" ", "\t")) and line.strip() and actions:
            actions[-1] = f"{actions[-1]} {line.strip()}"  # continuation of a wrapped bullet
    return tuple(a for a in actions if a)[:MAX_ACTIONS_PER_RUNBOOK]


def runbook_path(rule: CompiledRule) -> Path | None:
    """Return where ``rule``'s runbook lives, or None if it has none."""
    response = rule.meta.response
    if response is None:
        return None
    source = Path(rule.source) if rule.source else None
    if source is None or _is_builtin(source):
        return builtin_runbook_path(response)
    return source.parent / response


def _is_builtin(source: Path) -> bool:
    try:
        return source.resolve().is_relative_to(builtin_rules_dir().resolve())
    except OSError:
        return False


def _read(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(MAX_RUNBOOK_BYTES)
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def load_guidance(rules: Iterable[CompiledRule]) -> dict[str, RuleGuidance]:
    """Collect recommended actions and false positives for each rule, keyed by rule id.

    A missing or unreadable runbook gives no actions instead of an error: the incident is still
    useful without it.
    """
    guidance: dict[str, RuleGuidance] = {}
    for rule in rules:
        path = runbook_path(rule)
        actions = extract_actions(_read(path)) if path is not None else ()
        guidance[rule.id] = RuleGuidance(
            rule_id=rule.id,
            actions=actions,
            false_positives=tuple(rule.meta.falsepositives),
        )
    return guidance
