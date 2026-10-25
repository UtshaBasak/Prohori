"""Safe loading of rule files, with line numbers for every error.

* Files are limited to :data:`MAX_RULE_BYTES`, must be UTF-8 and contain one YAML document.
* Only ``yaml.SafeLoader`` is used, so tags such as ``!!python/object`` are rejected.
* Anchors and aliases are rejected: even safe loading expands alias graphs, and walking an
  expanded "billion laughs" document would take exponential time.
* Nesting depth and node count are bounded.
* Errors found by validation are mapped back to the line of the offending YAML node.
"""

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from prohori.rules.compiler import CompiledRule, compile_rule
from prohori.rules.matching import Path as DocPath
from prohori.rules.matching import RuleError

MAX_RULE_BYTES = 128 * 1024
MAX_NODES = 10_000
MAX_DEPTH = 32
RULE_SUFFIXES = (".yml", ".yaml")


class RuleLoadError(ValueError):
    """Raised when a rule file cannot be read as a single safe YAML document."""

    def __init__(self, message: str, line: int | None = None) -> None:
        super().__init__(message)
        self.line = line


@dataclass(frozen=True, slots=True)
class LocatedError:
    """A rule problem with its file line (``None`` when no line applies) and document path."""

    line: int | None
    path: str
    message: str

    def format(self, file: str) -> str:
        location = f"{file}:{self.line}" if self.line is not None else file
        return (
            f"{location}: {self.path}: {self.message}"
            if self.path
            else f"{location}: {self.message}"
        )


@dataclass
class RuleReport:
    """Validation outcome for one rule file."""

    file: Path
    rule: CompiledRule | None
    errors: list[LocatedError] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.rule is not None and not self.errors


def load_yaml(text: str) -> tuple[object, dict[DocPath, int]]:
    """Parse one YAML document safely; return the data and a map of document path to line.

    Raises:
        RuleLoadError: for invalid YAML, unsafe tags, aliases or excessive size.
    """
    loader = yaml.SafeLoader(text)
    try:
        node = loader.get_single_node()
        if node is None:
            raise RuleLoadError("the file is empty")
        lines: dict[DocPath, int] = {}
        _index(node, (), lines, set(), depth=0)
        data = loader.construct_document(node)
    except yaml.MarkedYAMLError as exc:
        mark = exc.problem_mark or exc.context_mark
        line = mark.line + 1 if mark is not None else None
        problem = exc.problem or exc.context or "invalid YAML"
        raise RuleLoadError(f"invalid YAML: {problem}", line) from None
    except yaml.YAMLError as exc:
        raise RuleLoadError(f"invalid YAML: {exc}") from None
    finally:
        loader.dispose()
    return data, lines


def _index(
    node: yaml.Node, path: DocPath, lines: dict[DocPath, int], seen: set[int], depth: int
) -> None:
    if id(node) in seen:
        raise RuleLoadError("YAML anchors and aliases are not allowed", node.start_mark.line + 1)
    seen.add(id(node))
    if len(seen) > MAX_NODES:
        raise RuleLoadError(f"more than {MAX_NODES} YAML nodes")
    if depth > MAX_DEPTH:
        raise RuleLoadError(f"nested deeper than {MAX_DEPTH} levels", node.start_mark.line + 1)
    lines.setdefault(path, node.start_mark.line + 1)
    if isinstance(node, yaml.MappingNode):
        for key_node, value_node in node.value:
            key = key_node.value if isinstance(key_node, yaml.ScalarNode) else "?"
            child = (*path, str(key))
            lines[child] = key_node.start_mark.line + 1
            _index(key_node, (*child, "<key>"), lines, seen, depth + 1)
            _index(value_node, child, lines, seen, depth + 1)
    elif isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            lines[(*path, index)] = item.start_mark.line + 1
            _index(item, (*path, index), lines, seen, depth + 1)


def _line_for(path: DocPath, lines: dict[DocPath, int]) -> int | None:
    for end in range(len(path), -1, -1):
        line = lines.get(tuple(str(p) if isinstance(p, str) else p for p in path[:end]))
        if line is not None:
            return line
    return None


def _format_path(path: DocPath) -> str:
    parts: list[str] = []
    for part in path:
        if isinstance(part, int):
            parts.append(f"[{part}]")
        else:
            parts.append(("." if parts else "") + part)
    return "".join(parts)


def load_rule(file: Path) -> RuleReport:
    """Read, validate and compile one rule file."""
    try:
        data = file.read_bytes()
    except OSError as exc:
        return RuleReport(file, None, [LocatedError(None, "", f"cannot read file: {exc.strerror}")])
    if len(data) > MAX_RULE_BYTES:
        return RuleReport(
            file, None, [LocatedError(None, "", f"file larger than {MAX_RULE_BYTES} bytes")]
        )
    try:
        text = data.decode("utf-8")
        document, lines = load_yaml(text)
    except UnicodeDecodeError:
        return RuleReport(file, None, [LocatedError(None, "", "file is not valid UTF-8")])
    except RuleLoadError as exc:
        return RuleReport(file, None, [LocatedError(exc.line, "", str(exc))])
    result = compile_rule(document, source=str(file))
    errors = [_locate(error, lines) for error in result.errors]
    return RuleReport(file, result.rule, errors)


def _locate(error: RuleError, lines: dict[DocPath, int]) -> LocatedError:
    return LocatedError(_line_for(error.path, lines), _format_path(error.path), error.message)


def discover(paths: list[Path]) -> Iterator[Path]:
    """Yield rule files: the given files, and ``*.yml`` / ``*.yaml`` under given directories.

    Directories are walked recursively in sorted order so output is deterministic.
    """
    for path in paths:
        if path.is_dir():
            yield from sorted(
                p for p in path.rglob("*") if p.is_file() and p.suffix.lower() in RULE_SUFFIXES
            )
        else:
            yield path


def load_rules(paths: list[Path]) -> list[RuleReport]:
    """Load every rule under ``paths`` and flag duplicate rule ids across files."""
    reports = [load_rule(file) for file in discover(paths)]
    first_seen: dict[str, Path] = {}
    for report in reports:
        if report.rule is None:
            continue
        rule_id = report.rule.id
        if rule_id in first_seen:
            report.errors.append(
                LocatedError(
                    None, "id", f"duplicate rule id {rule_id!r} (also in {first_seen[rule_id]})"
                )
            )
        else:
            first_seen[rule_id] = report.file
    return reports
