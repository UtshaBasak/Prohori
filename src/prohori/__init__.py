"""Prohori: a laptop-sized security-operations pipeline.

Parses logs into a common event schema, detects suspicious activity with YAML rules and
machine-learning models, enriches indicators, groups alerts into incidents and reports them.
"""

from prohori.version import __version__

__all__ = ["__version__"]
