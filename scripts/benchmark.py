# SPDX-License-Identifier: LicenseRef-PolyForm-Strict-1.0.0
# Copyright (c) 2026 Utsha Basak
"""Measure throughput and peak memory on logs of at least a million lines.

Builds one log per input format from the simulator: chunk after chunk of busy background
activity and the scenario's attack, each with its own seed and later in time, until the log has
``--lines`` lines. Then it runs, each in its own process:

* ``prohori incidents`` on every log (parse, rules, offline enrichment, incidents, JSON output);
* ``prohori pipeline replay`` (lite mode) on the access log, unless ``--no-pipeline``;
* ``prohori demo``.

For each run it records the wall-clock time, lines per second, the process's peak memory (peak
resident set on Linux and macOS, peak working set on Windows) and the exit code, with the
machine it ran on, in ``results/performance.json``.

``--alerts N`` instead measures an alert storm: an application log of ``N`` lines in which every
line raises an alert (an admin role granted, from 762 addresses), through ``detect -f json``,
the ``detect`` table and ``incidents``. Each must stay under :data:`STORM_BOUND_MIB` of peak
memory, however many alerts there are; the result is merged into the ``alert_storm`` part of the
results file and the other measurements are kept. Run it directly, as below: on Linux a child's
peak memory includes its parent's from before ``exec``, so a large parent inflates the numbers.
Then run ``scripts/generate_results_table.py`` to update the tables in ``docs/PERFORMANCE.md``
and the README. The logs and outputs go to ``--work`` (git-ignored ``data/benchmark/`` by
default) and are deleted afterwards unless ``--keep``.

    uv run --extra pipeline python scripts/benchmark.py [--lines 1000000]
    uv run python scripts/benchmark.py --alerts 1000000
"""

import argparse
import ctypes
import json
import math
import os
import platform
import random
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from prohori import __version__
from prohori.simulate.addresses import AddressPool
from prohori.simulate.model import Recorder
from prohori.simulate.run import get_scenario, resolve_params

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "results" / "performance.json"
DEFAULT_WORK = ROOT / "data" / "benchmark"
FORMAT = "prohori.performance/1"
#: Parser -> the scenario whose background and attack fill the log, and the background per chunk:
#: (minutes, events a minute). SSH background takes a new address for every probe, so its chunks
#: stay at the scenario's defaults.
LOGS = {
    "access_log": ("web-scanning", 1440, 60.0),
    "auth_log": ("ssh-bruteforce", 180, 1.5),
    "app_json": ("account-takeover", 1440, 60.0),
}
#: Peak memory every alert-storm run must stay under, in MiB.
STORM_BOUND_MIB = 512
#: The documentation address ranges, one address per alert in turn.
STORM_ADDRESSES = tuple(
    f"{network}.{host}"
    for network in ("192.0.2", "198.51.100", "203.0.113")
    for host in range(1, 255)
)
#: Chunks follow one another from here; auth_log has no year, and every log stays inside 2026.
BASE = datetime(2026, 1, 1, tzinfo=UTC)
YEAR = 2026


def build_log(parser: str, lines: int, path: Path) -> int:
    """Write a log of at least ``lines`` lines for ``parser``; return the number written.

    Each chunk is the scenario (background and attack) with its own seed. It starts two hours after
    the previous chunk's background ended (the attack can run past the background), so timestamps
    keep moving forward.
    """
    name, minutes, noise = LOGS[parser]
    minutes = min(minutes, max(10, math.ceil(lines / noise)))  # small logs for the tests
    scenario = get_scenario(name)
    params, _ = resolve_params(scenario, "default", {"duration": str(minutes), "noise": str(noise)})
    written = 0
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        chunk = 0
        while written < lines:
            rng = random.Random(f"benchmark:{parser}:{chunk}")  # noqa: S311 - reproducible on purpose
            recorder = Recorder(rng, BASE + timedelta(minutes=(minutes + 120) * chunk))
            scenario.generate(recorder, AddressPool(rng), params, "default")
            for text, _ in recorder.lines():
                stream.write(text + "\n")
                written += 1
            chunk += 1
    return written


def build_alert_storm(alerts: int, path: Path) -> int:
    """Write an app log of ``alerts`` lines, each one an admin role grant (PRH-ADMIN-001)."""
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for n in range(alerts):
            when = BASE + timedelta(milliseconds=100 * n)
            record = {
                "time": when.isoformat().replace("+00:00", "Z"),
                "event": {"action": "admin.role.granted", "category": "admin"},
                "source": {"ip": STORM_ADDRESSES[n % len(STORM_ADDRESSES)]},
                "user": {"id": f"u-{n % 5000:04d}"},
            }
            stream.write(json.dumps(record, separators=(",", ":")) + "\n")
    return alerts


def _summary(work: Path, name: str) -> dict[str, Any]:
    """The JSON summary a command printed last on standard error."""
    lines = (work / f"{name}.err").read_text(encoding="utf-8", errors="replace").splitlines()
    for line in reversed(lines):
        if line.startswith("{"):
            found: dict[str, Any] = json.loads(line)
            return found
    return {}


def run_storm(alerts: int, work: Path) -> dict[str, Any]:
    """Measure the commands on an alert storm; see the module documentation."""
    work.mkdir(parents=True, exist_ok=True)
    log = work / "alert-storm.jsonl"
    build_alert_storm(alerts, log)
    base = [log.as_posix(), "-p", "app_json", "--exit-zero"]
    commands = {
        "storm-detect-json": ["detect", *base, "-f", "json"],
        "storm-detect-table": ["detect", *base],
        "storm-incidents": ["incidents", *base, "-f", "json"],
    }
    runs = []
    for name, args in commands.items():
        found = measure(args, work, name)
        summary = _summary(work, name)
        found |= {
            "lines": alerts,
            "bytes": log.stat().st_size,
            "lines_per_second": round(alerts / found["seconds"]),
            "alerts": summary.get("alerts"),
            "alerts_not_kept": summary.get("alerts_not_kept", 0),
            "within_bound": found["peak_memory_mib"] <= STORM_BOUND_MIB,
        }
        runs.append(found)
    return {"alerts": alerts, "bound_mib": STORM_BOUND_MIB, "runs": runs}


def _peak_windows(process: subprocess.Popen[bytes]) -> int:
    class Counters(ctypes.Structure):
        _fields_ = [  # the layout of PROCESS_MEMORY_COUNTERS
            ("cb", ctypes.c_ulong),
            ("PageFaultCount", ctypes.c_ulong),
            ("PeakWorkingSetSize", ctypes.c_size_t),
            ("WorkingSetSize", ctypes.c_size_t),
            ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPagedPoolUsage", ctypes.c_size_t),
            ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
            ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
            ("PagefileUsage", ctypes.c_size_t),
            ("PeakPagefileUsage", ctypes.c_size_t),
        ]

    counters = Counters()
    counters.cb = ctypes.sizeof(Counters)
    psapi = ctypes.WinDLL("psapi")  # type: ignore[attr-defined,unused-ignore]
    psapi.GetProcessMemoryInfo.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_ulong]
    handle = int(process._handle)  # type: ignore[attr-defined]  # Windows only
    if not psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
        raise OSError("GetProcessMemoryInfo failed")
    return int(counters.PeakWorkingSetSize)


def _interpreter() -> tuple[str, dict[str, str] | None]:
    """The Python to run, so the process measured is Prohori itself.

    A virtual environment's python.exe on Windows is a launcher that starts the real interpreter
    as a second process; started directly with ``__PYVENV_LAUNCHER__``, the real interpreter uses
    the same environment in one process.
    """
    if sys.platform == "win32" and sys.prefix != sys.base_prefix:
        base = str(getattr(sys, "_base_executable", sys.executable))
        return base, {**os.environ, "__PYVENV_LAUNCHER__": sys.executable}
    return sys.executable, None


def measure(args: list[str], work: Path, name: str) -> dict[str, Any]:
    """Run ``prohori ARGS`` in its own process; time it and read its peak memory."""
    stdout, stderr = work / f"{name}.out", work / f"{name}.err"
    executable, env = _interpreter()
    command = [executable, "-m", "prohori", *args]
    with stdout.open("wb") as out, stderr.open("wb") as err:
        started = time.perf_counter()
        process = subprocess.Popen(command, stdout=out, stderr=err, env=env)  # noqa: S603
        if sys.platform == "win32":
            code = process.wait()
            seconds = time.perf_counter() - started
            peak = _peak_windows(process)
        else:
            _, status, usage = os.wait4(process.pid, 0)
            seconds = time.perf_counter() - started
            process.returncode = code = os.waitstatus_to_exitcode(status)
            # ru_maxrss is in bytes on macOS and in KiB on Linux.
            peak = usage.ru_maxrss if sys.platform == "darwin" else usage.ru_maxrss * 1024
    with stdout.open(encoding="utf-8", errors="replace") as found:
        output_lines = sum(1 for _ in found)
    return {
        "name": name,
        "command": "prohori " + " ".join(a.replace(work.as_posix(), "WORK") for a in args),
        "seconds": round(seconds, 2),
        "peak_memory_mib": round(peak / 2**20, 1),
        "exit_code": code,
        "output_lines": output_lines,
    }


def _size(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def run(lines: int, work: Path, *, pipeline: bool = True) -> dict[str, Any]:
    work.mkdir(parents=True, exist_ok=True)
    runs = []
    for parser in LOGS:
        log = work / f"{parser}.log"
        count = build_log(parser, lines, log)
        args = ["incidents", log.as_posix(), "-p", parser, "-f", "json", "--exit-zero"]
        if parser == "auth_log":
            args += ["--year", str(YEAR)]
        found = measure(args, work, f"incidents-{parser}")
        found |= {
            "parser": parser,
            "lines": count,
            "bytes": log.stat().st_size,
            "lines_per_second": round(count / found["seconds"]),
            "enrichment": "offline",
        }
        runs.append(found)
        if pipeline and parser == "access_log":
            state = work / "pipeline-state"
            replay = ["pipeline", "replay", log.as_posix(), "-p", parser]
            found = measure([*replay, "--state", state.as_posix()], work, "pipeline-replay")
            found |= {
                "parser": parser,
                "lines": count,
                "bytes": log.stat().st_size,
                "lines_per_second": round(count / found["seconds"]),
                "enrichment": "offline",
                "state_bytes": _size(state),
            }
            runs.append(found)
    runs.append(measure(["demo", "--out", (work / "demo").as_posix()], work, "demo"))
    return {
        "format": FORMAT,
        "date": datetime.now(UTC).date().isoformat(),
        "target_lines": lines,
        "machine": {
            "system": f"{platform.system()} {platform.release()}",
            "machine": platform.machine(),
            "processor": platform.processor() or "unknown",
            "cpus": os.cpu_count(),
            "python": platform.python_version(),
            "prohori": __version__,
        },
        "runs": runs,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--lines", type=int, default=1_000_000, help="lines per log (at least)")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT, help="results file to write")
    parser.add_argument("--work", type=Path, default=DEFAULT_WORK, help="directory for the logs")
    parser.add_argument("--no-pipeline", action="store_true", help="skip the lite-mode replay")
    parser.add_argument("--keep", action="store_true", help="keep the logs and outputs")
    parser.add_argument(
        "--alerts", type=int, default=0, help="measure an alert storm of this many alerts instead"
    )
    args = parser.parse_args(argv)
    if args.lines < 1:
        parser.error("--lines must be positive")
    if args.alerts < 0:
        parser.error("--alerts must not be negative")
    if args.alerts:
        return _storm_main(args.alerts, args.out, args.work, keep=args.keep)
    try:
        results = run(args.lines, args.work, pipeline=not args.no_pipeline)
    finally:
        if not args.keep:
            shutil.rmtree(args.work, ignore_errors=True)
    failed = [r["name"] for r in results["runs"] if r["exit_code"] != 0]
    previous = _load(args.out)
    if previous is not None and "alert_storm" in previous:
        results["alert_storm"] = previous["alert_storm"]  # measured separately; keep it
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {args.out}")
    if failed:
        print(f"failed: {', '.join(failed)}", file=sys.stderr)
        return 1
    return 0


def _load(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    found: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return found


def _storm_main(alerts: int, out: Path, work: Path, *, keep: bool) -> int:
    try:
        storm = run_storm(alerts, work)
    finally:
        if not keep:
            shutil.rmtree(work, ignore_errors=True)
    results = _load(out)
    if results is None:
        print(f"{out} does not exist yet: run the main benchmark first", file=sys.stderr)
        return 1
    results["alert_storm"] = storm | {"date": datetime.now(UTC).date().isoformat()}
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {out}")
    bad = [r["name"] for r in storm["runs"] if r["exit_code"] != 0 or not r["within_bound"]]
    if bad:
        print(f"failed or over {STORM_BOUND_MIB} MiB: {', '.join(bad)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
