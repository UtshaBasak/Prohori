"""Optional LLM incident analyst: providers, redaction before sending, and explanations.

Off by default. Nothing is sent anywhere unless ``PROHORI_LLM_PROVIDER`` names a provider that
sends (``gemini``); the payload is always redacted first (:mod:`prohori.llm.payload`). The
Gemini provider needs the ``llm`` extra and raises :class:`MissingExtraError` without it.
"""


class MissingExtraError(ImportError):
    """The ``llm`` extra is not installed."""

    def __init__(self, module: str) -> None:
        super().__init__(
            f"{module} needs the 'llm' extra: pip install 'prohori[llm]' (or uv sync --extra llm)"
        )
