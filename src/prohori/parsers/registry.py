"""Registry of available parsers by name."""

from collections.abc import Callable
from typing import TypeVar

from prohori.parsers.base import LineParser

P = TypeVar("P", bound=type[LineParser])

_REGISTRY: dict[str, type[LineParser]] = {}


def register(cls: P) -> P:
    """Class decorator that registers a parser under its ``name``."""
    if not cls.name:
        msg = f"{cls.__name__} must define a non-empty 'name'"
        raise ValueError(msg)
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        msg = f"parser name {cls.name!r} is already registered"
        raise ValueError(msg)
    _REGISTRY[cls.name] = cls
    return cls


def available() -> list[str]:
    """Return the names of all registered parsers, sorted."""
    return sorted(_REGISTRY)


def get_parser(name: str, **options: object) -> LineParser:
    """Create the parser registered as ``name`` with parser-specific ``options``.

    Raises:
        KeyError: if no parser has that name.
    """
    try:
        factory: Callable[..., LineParser] = _REGISTRY[name]
    except KeyError:
        msg = f"unknown parser {name!r}; available: {', '.join(available()) or 'none'}"
        raise KeyError(msg) from None
    return factory(**options)
