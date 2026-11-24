# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Flat, dotted-path access to event fields (``event.action``, ``source.ip``, ...).

Models are nested, but rules and features refer to fields by dotted name as in the schema
documentation. This module is the single mapping between the two.
"""

from enum import Enum
from ipaddress import IPv4Address, IPv6Address, ip_network
from typing import get_args

from pydantic import BaseModel

from prohori.schema.event import Event
from prohori.schema.types import JsonScalar


def _model(annotation: object) -> type[BaseModel] | None:
    """The model class of a field annotated ``Model`` or ``Model | None``."""
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        return annotation
    for arg in get_args(annotation):
        if isinstance(arg, type) and issubclass(arg, BaseModel):
            return arg
    return None


def _paths(model: type[BaseModel], prefix: str) -> list[str]:
    paths: list[str] = []
    for name, info in model.model_fields.items():
        nested = _model(info.annotation)
        if nested is not None:
            paths.extend(_paths(nested, f"{prefix}{name}."))
        else:
            paths.append(f"{prefix}{name}")
    return paths


def _collect_paths() -> tuple[str, ...]:
    return tuple(p for p in _paths(Event, "") if not p.startswith("extra"))


#: Every dotted field path an event exposes, excluding ``extra.*`` (which is open-ended).
FIELD_PATHS: frozenset[str] = frozenset(_collect_paths())

#: Fields computed from others when read, never stored: ``source.ip_prefix`` is the network of
#: ``source.ip`` (a /24 for IPv4, a /48 for IPv6), for rules that count per network.
DERIVED_PATHS: frozenset[str] = frozenset({"source.ip_prefix"})
IPV4_PREFIX = 24
IPV6_PREFIX = 48


def is_valid_path(path: str) -> bool:
    """Return whether ``path`` names an event field (``extra.<key>`` is always accepted).

    Derived fields (:data:`DERIVED_PATHS`) are valid: they can be read, but not set.
    """
    if path.startswith("extra."):
        return len(path) > len("extra.")
    return path in FIELD_PATHS or path in DERIVED_PATHS


def ip_prefix(address: IPv4Address | IPv6Address) -> str:
    """The network a rule counts ``address`` in: its /24 (IPv4) or /48 (IPv6)."""
    bits = IPV4_PREFIX if isinstance(address, IPv4Address) else IPV6_PREFIX
    return str(ip_network((address, bits), strict=False))


def get_field(event: Event, path: str) -> JsonScalar:
    """Return the value at a dotted ``path`` as a JSON scalar, or ``None`` if unset.

    Enums are returned as their string value, IP addresses as strings and timestamps in ISO-8601.

    Raises:
        KeyError: if ``path`` is not a known field path.
    """
    if not is_valid_path(path):
        raise KeyError(path)
    if path == "source.ip_prefix":
        return ip_prefix(event.source.ip) if event.source.ip is not None else None
    head, _, tail = path.partition(".")
    if head == "extra":
        return event.extra.get(tail)
    value: object = event
    for part in path.split("."):
        value = getattr(value, part)
        if value is None:  # an unset group such as ``process`` (or ``process.parent``)
            return None
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
