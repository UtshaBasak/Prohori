# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Suppressions and allow-lists: reviewed, expiring, visible exceptions to detection.

See ``docs/RULES.md`` (the file format and the semantics) and ADR-0043.
"""

from prohori.suppress.apply import MAX_LISTED, MAX_TRACKED_EVENTS, Suppressor
from prohori.suppress.entries import ANY_RULE, AllowIpDocument, Entry, EntryDocument
from prohori.suppress.loader import (
    NO_SUPPRESSIONS,
    SuppressionFileError,
    Suppressions,
    load_suppressions,
    parse_suppressions,
)

__all__ = [
    "ANY_RULE",
    "MAX_LISTED",
    "MAX_TRACKED_EVENTS",
    "NO_SUPPRESSIONS",
    "AllowIpDocument",
    "Entry",
    "EntryDocument",
    "SuppressionFileError",
    "Suppressions",
    "Suppressor",
    "load_suppressions",
    "parse_suppressions",
]
