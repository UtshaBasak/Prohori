"""``--models``: run the anomaly detectors next to the rules on the same parsed events."""

from collections.abc import Iterable, Iterator
from typing import Annotated

import typer

from prohori.ml import anomaly
from prohori.ml.features import FeatureExtractor
from prohori.schema import Alert, Event

ModelsOption = Annotated[
    bool,
    typer.Option(
        "--models",
        help="Also flag unusual source IPs with the anomaly detectors (robust z-score, and the "
        "Isolation Forest when the ml extra is installed) over 5-minute windows.",
    ),
]


def _has_iforest() -> bool:
    try:
        import sklearn.ensemble  # noqa: F401
    except ImportError:
        return False
    return True


class ModelRun:
    """Observes events as they stream to the rules, then raises the anomaly alerts."""

    def __init__(self, enabled: bool) -> None:
        self.extractor = FeatureExtractor() if enabled else None

    def observe(self, events: Iterable[Event]) -> Iterable[Event]:
        return self.extractor.observe_all(events) if self.extractor is not None else events

    def alerts(self) -> list[Alert]:
        """The anomaly alerts; call once every event has been observed."""
        if self.extractor is None:
            return []
        windows = self.extractor.windows()
        detectors = list(anomaly.CLI_DETECTORS)
        if not _has_iforest():
            detectors.remove("iforest")
            typer.echo(
                "note: the Isolation Forest needs the ml extra (pip install 'prohori[ml]'); "
                "running the z-score detector only",
                err=True,
            )
        if len(windows) < anomaly.MIN_WINDOWS:
            typer.echo(
                f"note: --models needs at least {anomaly.MIN_WINDOWS} source-IP windows to "
                f"judge what is unusual; this input has {len(windows)}",
                err=True,
            )
        return anomaly.detect(windows, detectors)

    def chain(self, alerts: Iterable[Alert]) -> Iterator[Alert]:
        """``alerts`` followed by the anomaly alerts, computed once ``alerts`` is exhausted."""
        yield from alerts
        yield from self.alerts()
