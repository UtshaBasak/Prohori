"""Bundled, synthetic enrichment data for offline runs, tests and demos.

The fixture covers only documentation addresses (RFC 5737 and RFC 3849), which never reach real
providers or the real cache, so fake and real data cannot mix.
"""

import json
from datetime import datetime, timedelta
from importlib.resources import files
from typing import ClassVar

from prohori.enrich.addresses import IPAddress
from prohori.enrich.provider import Provider, ProviderData
from prohori.schema import JsonScalar


class OfflineProvider(Provider):
    """Answers from the bundled fixture ``prohori/enrich/data/offline.json``."""

    name: ClassVar[str] = "offline"
    external: ClassVar[bool] = False
    note: ClassVar[str] = "Synthetic offline fixture for documentation addresses; not real data."

    def __init__(self) -> None:
        super().__init__(ttl=timedelta(0))
        raw = json.loads(files("prohori.enrich").joinpath("data/offline.json").read_text("utf-8"))
        self.retrieved_at_fixed = datetime.fromisoformat(raw["retrieved_at"])
        self._data: dict[str, dict[str, JsonScalar]] = raw["addresses"]

    def retrieved_at(self, now: datetime) -> datetime:
        return self.retrieved_at_fixed

    def lookup(self, address: IPAddress) -> ProviderData | None:
        found = self._data.get(str(address))
        return dict(found) if found is not None else None

    def addresses(self) -> list[str]:
        """Return the addresses the fixture knows."""
        return sorted(self._data)
