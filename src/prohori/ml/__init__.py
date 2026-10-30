"""Machine-learning detection: datasets, features, training, evaluation and scoring.

Importing this package needs nothing beyond the base install. The modules that use pandas or
scikit-learn (``datasets``, ``cleaning``) raise :class:`MissingExtraError` with the install
command when the ``ml`` extra is absent.
"""


class MissingExtraError(ImportError):
    """The ``ml`` extra is not installed."""

    def __init__(self, module: str) -> None:
        super().__init__(
            f"{module} needs the 'ml' extra: pip install 'prohori[ml]' (or uv sync --extra ml)"
        )
