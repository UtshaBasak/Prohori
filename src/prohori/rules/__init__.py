"""YAML detection rules: format, safe loading, validation, matching and evaluation."""

from importlib.resources import files
from pathlib import Path

from prohori.rules.compiler import CompiledRule, CompileResult, compile_rule
from prohori.rules.condition import ConditionError, parse_condition
from prohori.rules.engine import EngineStats, RuleEngine
from prohori.rules.loader import LocatedError, RuleLoadError, RuleReport, load_rule, load_rules
from prohori.rules.matching import RuleError, wildcard_match
from prohori.rules.model import AggregateSpec, RuleMeta, SequenceSpec, parse_duration
from prohori.rules.regex_safety import UnsafeRegexError, check_regex


def builtin_rules_dir() -> Path:
    """Return the directory holding the packaged built-in rules."""
    return Path(str(files("prohori.rules") / "builtin"))


__all__ = [
    "AggregateSpec",
    "CompileResult",
    "CompiledRule",
    "ConditionError",
    "EngineStats",
    "LocatedError",
    "RuleEngine",
    "RuleError",
    "RuleLoadError",
    "RuleMeta",
    "RuleReport",
    "SequenceSpec",
    "UnsafeRegexError",
    "builtin_rules_dir",
    "check_regex",
    "compile_rule",
    "load_rule",
    "load_rules",
    "parse_condition",
    "parse_duration",
    "wildcard_match",
]
