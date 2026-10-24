"""Process exit codes shared by all commands."""

from enum import IntEnum


class ExitCode(IntEnum):
    """Exit codes. ``2`` is also what Typer uses for usage errors."""

    OK = 0
    NO_EVENTS = 1
    USAGE = 2
