"""Small helpers shared by parsers."""

import json
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Any

from prohori.parsers.base import ParseError, sanitize


def normalise_ip(text: str | None) -> IPv4Address | IPv6Address | None:
    """Parse an IP address, mapping IPv4-mapped IPv6 to IPv4. Returns ``None`` if not an address."""
    if not text:
        return None
    try:
        address = ip_address(text.strip("[]"))
    except ValueError:
        return None
    if isinstance(address, IPv6Address) and address.ipv4_mapped is not None:
        return address.ipv4_mapped
    return address


def _clean(value: object) -> object:
    if isinstance(value, str):
        return sanitize(value)
    if isinstance(value, list):
        return [_clean(item) for item in value]
    return value


def _clean_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    return {sanitize(key): _clean(value) for key, value in pairs}


def load_json_object(line: str) -> dict[str, Any]:
    """Decode one JSON Lines record, which must be an object.

    The line was sanitised before decoding, but JSON escapes such as ``\u001b`` decode to
    control characters again; every key and string value is sanitised once more.
    """
    try:
        value = json.loads(line, object_pairs_hook=_clean_object)
    except RecursionError:  # deeply nested input
        raise ParseError("JSON nested too deeply") from None
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc.msg} at column {exc.colno}") from None
    if not isinstance(value, dict):
        raise ParseError(f"JSON record is a {type(value).__name__}, not an object")
    return value


def get_path(record: dict[str, Any], path: str) -> object:
    """Return the value at a dotted ``path`` in nested dictionaries, or ``None`` if absent."""
    value: object = record
    for part in path.split("."):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def as_text(value: object) -> str | None:
    """Return a scalar as text (``None`` and empty strings become ``None``); reject containers."""
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str | int | float):
        return str(value)
    raise ParseError(f"expected a scalar, got {type(value).__name__}")
