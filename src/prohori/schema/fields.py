"""Flat, dotted-path access to event fields (``event.action``, ``source.ip``, ...).

Models are nested, but rules and features refer to fields by dotted name as in the schema
documentation. This module is the single mapping between the two.
"""

from enum import Enum
from ipaddress import IPv4Address, IPv6Address

from pydantic import BaseModel

from prohori.schema.event import Event
from prohori.schema.types import JsonScalar

_NESTED = ("event", "source", "user", "http")


def _collect_paths() -> tuple[str, ...]:
    paths: list[str] = []
    for name, info in Event.model_fields.items():
        if name == "extra":
            continue
        if name in _NESTED:
            nested = info.annotation
            if not (isinstance(nested, type) and issubclass(nested, BaseModel)):
                msg = f"Event.{name} must be a nested model"
                raise TypeError(msg)
            paths.extend(f"{name}.{sub}" for sub in nested.model_fields)
        else:
            paths.append(name)
    return tuple(paths)


#: Every dotted field path an event exposes, excluding ``extra.*`` (which is open-ended).
FIELD_PATHS: frozenset[str] = frozenset(_collect_paths())


def is_valid_path(path: str) -> bool:
    """Return whether ``path`` names an event field (``extra.<key>`` is always accepted)."""
    if path.startswith("extra."):
        return len(path) > len("extra.")
    return path in FIELD_PATHS


def get_field(event: Event, path: str) -> JsonScalar:
    """Return the value at a dotted ``path`` as a JSON scalar, or ``None`` if unset.

    Enums are returned as their string value, IP addresses as strings and timestamps in ISO-8601.

    Raises:
        KeyError: if ``path`` is not a known field path.
    """
    if not is_valid_path(path):
        raise KeyError(path)
    head, _, tail = path.partition(".")
    if head == "extra":
        return event.extra.get(tail)
    value: object = getattr(event, head)
    if tail:
        value = getattr(value, tail)
    return _to_scalar(value)


def _to_scalar(value: object) -> JsonScalar:
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, IPv4Address | IPv6Address):
        return str(value)
    if isinstance(value, str):
        return value
    isoformat = getattr(value, "isoformat", None)
    if callable(isoformat):
        return str(isoformat())
    msg = f"unsupported field type: {type(value).__name__}"
    raise TypeError(msg)
