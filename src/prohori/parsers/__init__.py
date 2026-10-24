"""Streaming parsers that turn raw log formats into common-schema events."""

from prohori.parsers.access_log import AccessLogParser
from prohori.parsers.app_json import AppJsonParser
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
from prohori.parsers.detect import detect_format
from prohori.parsers.generic_json import FieldMapping, GenericJsonParser, load_mapping
from prohori.parsers.registry import available, get_parser, register

__all__ = [
    "MAX_LINE_LENGTH",
    "AccessLogParser",
    "AppJsonParser",
    "AuthLogParser",
    "FieldMapping",
    "GenericJsonParser",
    "LineParser",
    "ParseError",
    "ParseStats",
    "RawLine",
    "available",
    "detect_format",
    "get_parser",
    "iter_text_lines",
    "load_mapping",
    "read_lines",
    "register",
    "sanitize",
]
