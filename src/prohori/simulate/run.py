"""Run a scenario and write its log, per-line labels and a manifest."""

import hashlib
import json
import random
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from prohori.simulate.addresses import AddressPool
from prohori.simulate.model import PARAMS, Attack, Recorder, SimulationError, parse_start
from prohori.simulate.scenarios import SCENARIOS, VARIANTS, Scenario

MANIFEST = "manifest.json"
MANIFEST_FORMAT = "prohori.simulation/1"


@dataclass(frozen=True)
class Simulation:
    """A generated scenario run, in memory."""

    scenario: Scenario
    variant: str
    seed: int
    params: dict[str, float]
    start: str
    lines: list[tuple[str, str | None]]  # (text, attack id or None), in file order
    attacks: list[Attack]

    @property
    def year(self) -> int:
        """The year of the first line, which the auth_log parser needs (syslog has no year)."""
        return int(self.start[:4])

    def log_text(self) -> str:
        return "".join(f"{text}\n" for text, _ in self.lines)

    def labels_text(self) -> str:
        return "".join(
            json.dumps({"line": n, "attack": attack}) + "\n"
            for n, (_, attack) in enumerate(self.lines, start=1)
        )


def get_scenario(name: str) -> Scenario:
    try:
        return SCENARIOS[name]
    except KeyError:
        choices = ", ".join(sorted(SCENARIOS))
        raise SimulationError(f"unknown scenario {name!r}; choose from {choices}") from None


def resolve_params(
    scenario: Scenario, variant: str, overrides: Mapping[str, str] | None = None
) -> tuple[dict[str, float], str]:
    """The scenario's defaults for ``variant`` with ``overrides`` applied and validated."""
    if variant not in VARIANTS:
        raise SimulationError(f"unknown variant {variant!r}; choose from {', '.join(VARIANTS)}")
    params = dict(scenario.defaults[variant])
    start = scenario.starts[variant]
    for name, text in (overrides or {}).items():
        if name == "start":
            parse_start(text)
            start = text
            continue
        if name not in params:
            allowed = ", ".join(["start", *sorted(params)])
            raise SimulationError(f"{scenario.name} has no parameter {name!r}; use {allowed}")
        params[name] = PARAMS[name].coerce(name, text)
    return params, start


def simulate(
    name: str,
    *,
    seed: int,
    variant: str = "default",
    overrides: Mapping[str, str] | None = None,
) -> Simulation:
    """Generate one scenario run. The same arguments always give the same lines."""
    scenario = get_scenario(name)
    params, start = resolve_params(scenario, variant, overrides)
    rng = random.Random(f"{name}:{variant}:{seed}")  # noqa: S311 - reproducible on purpose
    recorder = Recorder(rng, parse_start(start))
    scenario.generate(recorder, AddressPool(rng), params, variant)
    return Simulation(scenario, variant, seed, params, start, recorder.lines(), recorder.attacks)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def write(simulation: Simulation, out_dir: Path) -> dict[str, object]:
    """Write the log, ``<name>.labels.jsonl`` and ``manifest.json``; return the manifest."""
    out_dir.mkdir(parents=True, exist_ok=True)
    scenario = simulation.scenario
    log = simulation.log_text().encode("utf-8")
    labels = simulation.labels_text().encode("utf-8")
    label_name = f"{scenario.name}.labels.jsonl"
    (out_dir / scenario.filename).write_bytes(log)
    (out_dir / label_name).write_bytes(labels)
    attack_lines = sum(1 for _, attack in simulation.lines if attack)
    manifest: dict[str, object] = {
        "format": MANIFEST_FORMAT,
        "scenario": scenario.name,
        "description": scenario.description,
        "variant": simulation.variant,
        "seed": simulation.seed,
        "start": simulation.start,
        "year": simulation.year,
        "params": simulation.params,
        "parser": scenario.parser,
        "files": {
            "log": {
                "name": scenario.filename,
                "sha256": _sha256(log),
                "lines": len(simulation.lines),
            },
            "labels": {"name": label_name, "sha256": _sha256(labels)},
        },
        "lines": {"attack": attack_lines, "benign": len(simulation.lines) - attack_lines},
        "attacks": [a.as_dict() for a in simulation.attacks],
        "note": "Synthetic data. Every IP address is from a documentation range.",
    }
    text = json.dumps(manifest, indent=2) + "\n"
    (out_dir / MANIFEST).write_bytes(text.encode("utf-8"))
    return manifest
