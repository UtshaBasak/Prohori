"""Streaming pipeline: producers, consumers, sinks and the lite-mode runner.

Lite mode runs every stage in one process over a file-based transport, without Docker. Importing
this package needs nothing beyond the base install; only the DuckDB sink needs the ``pipeline``
extra and raises :class:`MissingExtraError` without it.
"""


class MissingExtraError(ImportError):
    """The ``pipeline`` extra is not installed."""

    def __init__(self, module: str) -> None:
        super().__init__(
            f"{module} needs the 'pipeline' extra: pip install 'prohori[pipeline]' "
            "(or uv sync --extra pipeline)"
        )
