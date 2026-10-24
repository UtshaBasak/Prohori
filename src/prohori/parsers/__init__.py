"""Streaming parsers that turn raw log formats into common-schema events."""

from prohori.parsers.auth_log import AuthLogParser
from prohori.parsers.base import (
    MAX_LINE_LENGTH,
    LineParser,
    ParseError,
    ParseStats,
    RawLine,
    iter_text_lines,
    read_lines,
    sanitize,
)
from prohori.parsers.registry import available, get_parser, register

__all__ = [
    "MAX_LINE_LENGTH",
    "AuthLogParser",
    "LineParser",
    "ParseError",
    "ParseStats",
    "RawLine",
    "available",
    "get_parser",
    "iter_text_lines",
    "read_lines",
    "register",
    "sanitize",
]
