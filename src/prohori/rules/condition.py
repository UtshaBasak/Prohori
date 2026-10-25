"""Parser and evaluator for rule ``condition`` expressions (no ``eval``).

Grammar (keywords are case-insensitive)::

    expr     := or_expr
    or_expr  := and_expr ("or" and_expr)*
    and_expr := not_expr ("and" not_expr)*
    not_expr := "not" not_expr | atom
    atom     := "(" expr ")" | quant | NAME
    quant    := ("1" | "any" | "all") "of" (PATTERN | "them")

``NAME`` is a selection name (or the special blocks ``aggregate`` / ``sequence``); ``PATTERN`` is
a name prefix ending in ``*`` such as ``selection_*``. ``them`` means every selection.
"""

import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

MAX_CONDITION_LENGTH = 1_000
MAX_DEPTH = 32

#: Detection keys that are not selections.
SPECIAL_BLOCKS = frozenset({"aggregate", "sequence"})
NAME_PATTERN = r"[A-Za-z_][A-Za-z0-9_]*"

_TOKEN_RE = re.compile(rf"\s*(?:(?P<paren>[()])|(?P<word>{NAME_PATTERN}\*?|1|\S+))")
_KEYWORDS = frozenset({"and", "or", "not", "of", "them", "any", "all"})


class ConditionError(ValueError):
    """Raised for a condition that cannot be parsed or refers to unknown names."""


@dataclass(frozen=True, slots=True)
class Ref:
    """Reference to a selection or special block."""

    name: str


@dataclass(frozen=True, slots=True)
class Not:
    operand: "Node"


@dataclass(frozen=True, slots=True)
class And:
    operands: tuple["Node", ...]


@dataclass(frozen=True, slots=True)
class Or:
    operands: tuple["Node", ...]


@dataclass(frozen=True, slots=True)
class Quantifier:
    """``1 of x*`` / ``all of them``; ``names`` is resolved against the defined selections."""

    require_all: bool
    names: tuple[str, ...]


Node = Ref | Not | And | Or | Quantifier


def _tokenize(text: str) -> list[str]:
    tokens: list[str] = []
    position = 0
    while position < len(text):
        if text[position:].strip() == "":
            break
        match = _TOKEN_RE.match(text, position)
        if match is None:  # pragma: no cover - the pattern accepts any non-space run
            raise ConditionError(f"unexpected text at position {position}")
        token = match["paren"] or match["word"]
        if match["word"] and not re.fullmatch(rf"{NAME_PATTERN}\*?|1", token):
            raise ConditionError(f"unexpected token {token!r}")
        tokens.append(token)
        position = match.end()
    return tokens


class _Parser:
    def __init__(self, tokens: list[str], selections: Iterable[str]) -> None:
        self.tokens = tokens
        self.position = 0
        self.selections = sorted(selections)

    def peek(self) -> str | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def peek_keyword(self) -> str | None:
        token = self.peek()
        return token.lower() if token is not None else None

    def take(self) -> str:
        token = self.peek()
        if token is None:
            raise ConditionError("unexpected end of condition")
        self.position += 1
        return token

    def parse(self) -> Node:
        node = self.or_expr(0)
        if self.peek() is not None:
            raise ConditionError(f"unexpected {self.peek()!r} after the end of the expression")
        return node

    def or_expr(self, depth: int) -> Node:
        operands = [self.and_expr(depth)]
        while self.peek_keyword() == "or":
            self.take()
            operands.append(self.and_expr(depth))
        return operands[0] if len(operands) == 1 else Or(tuple(operands))

    def and_expr(self, depth: int) -> Node:
        operands = [self.not_expr(depth)]
        while self.peek_keyword() == "and":
            self.take()
            operands.append(self.not_expr(depth))
        return operands[0] if len(operands) == 1 else And(tuple(operands))

    def not_expr(self, depth: int) -> Node:
        if depth > MAX_DEPTH:
            raise ConditionError(f"condition nested deeper than {MAX_DEPTH} levels")
        if self.peek_keyword() == "not":
            self.take()
            return Not(self.not_expr(depth + 1))
        return self.atom(depth)

    def atom(self, depth: int) -> Node:
        item = self.take()
        lowered = item.lower()
        if item == "(":
            node = self.or_expr(depth + 1)
            if self.peek() != ")":
                raise ConditionError("expected ')'")
            self.take()
            return node
        if item == ")":
            raise ConditionError("unexpected ')'")
        if lowered in {"1", "any", "all"} and self.peek_keyword() == "of":
            self.take()
            return self.quantifier(require_all=lowered == "all")
        if lowered in _KEYWORDS or item == "1" or item.endswith("*"):
            raise ConditionError(f"unexpected {item!r}")
        return Ref(item)

    def quantifier(self, *, require_all: bool) -> Quantifier:
        target = self.take()
        if target.lower() == "them":
            names = self.selections
        elif target.endswith("*"):
            prefix = target[:-1]
            names = [name for name in self.selections if name.startswith(prefix)]
            if not names:
                raise ConditionError(f"no selection matches {target!r}")
        else:
            raise ConditionError(
                f"expected a pattern ending in '*' or 'them' after 'of', got {target!r}"
            )
        if not names:
            raise ConditionError("there are no selections to quantify over")
        return Quantifier(require_all, tuple(names))


def parse_condition(text: str, selections: Iterable[str]) -> Node:
    """Parse ``text`` into an expression tree.

    Raises:
        ConditionError: for syntax errors, excessive length or nesting.
    """
    if not isinstance(text, str) or not text.strip():
        raise ConditionError("condition must be a non-empty string")
    if len(text) > MAX_CONDITION_LENGTH:
        raise ConditionError(f"condition longer than {MAX_CONDITION_LENGTH} characters")
    return _Parser(_tokenize(text), selections).parse()


def references(node: Node) -> set[str]:
    """Return every name the expression refers to (including quantifier expansions)."""
    match node:
        case Ref(name):
            return {name}
        case Not(operand):
            return references(operand)
        case And(operands) | Or(operands):
            return set().union(*(references(o) for o in operands))
        case Quantifier(_, names):
            return set(names)
    raise TypeError(node)  # pragma: no cover


def evaluate(node: Node, lookup: Callable[[str], bool]) -> bool:
    """Evaluate the expression, calling ``lookup(name)`` for each referenced selection."""
    match node:
        case Ref(name):
            return lookup(name)
        case Not(operand):
            return not evaluate(operand, lookup)
        case And(operands):
            return all(evaluate(o, lookup) for o in operands)
        case Or(operands):
            return any(evaluate(o, lookup) for o in operands)
        case Quantifier(require_all, names):
            check = all if require_all else any
            return check(lookup(name) for name in names)
    raise TypeError(node)  # pragma: no cover


def split_special(node: Node) -> tuple[Node | None, set[str]]:
    """Separate top-level ``and`` terms that name special blocks from the stateless filter.

    Returns the filter expression (``None`` if nothing remains) and the special blocks found.

    Raises:
        ConditionError: if a special block appears anywhere other than as a top-level term.
    """
    terms = list(node.operands) if isinstance(node, And) else [node]
    specials = {t.name for t in terms if isinstance(t, Ref) and t.name in SPECIAL_BLOCKS}
    rest = [t for t in terms if not (isinstance(t, Ref) and t.name in SPECIAL_BLOCKS)]
    for term in rest:
        nested = references(term) & SPECIAL_BLOCKS
        if nested:
            name = sorted(nested)[0]
            raise ConditionError(f"'{name}' may only appear as a top-level 'and' term")
    if not rest:
        return None, specials
    return (rest[0] if len(rest) == 1 else And(tuple(rest))), specials
