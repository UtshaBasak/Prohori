"""Regenerate the committed examples: sample reports in ``docs/examples/`` and the demo image.

* ``docs/examples/account-takeover.md`` and ``.html``: the report of the sample incident.
* ``docs/examples/account-takeover-redacted.md``: the same with ``--redact-ips`` (a fixed,
  published key is used here so the example is reproducible; the command itself uses a random
  key every run).
* ``docs/images/demo.svg``: a terminal capture of ``prohori demo``.

With ``--check`` nothing is written and the exit code is 1 when a report example is out of date
(the image is not checked: its exact bytes depend on the installed Rich version).

    uv run python scripts/generate_examples.py [--check]
"""

import argparse
import hashlib
import io
import os
import sys
import tempfile
from pathlib import Path

from rich.console import Console

from prohori.cli.demo import DEFAULT_SCENARIOS, run_demo
from prohori.reports import ReportFormat, ReportSource, make_report
from prohori.schema import Incident

ROOT = Path(__file__).resolve().parents[1]
SAMPLE = next((ROOT / "samples" / "incidents").glob("INC-*.json"))
EXAMPLES = ROOT / "docs" / "examples"
IMAGE = ROOT / "docs" / "images" / "demo.svg"
#: Published on purpose: only for the reproducible example, never for real redaction.
EXAMPLE_KEY = b"prohori-example-key-not-secret!!"


def reports() -> dict[Path, str]:
    """The example report files and their expected contents."""
    data = SAMPLE.read_bytes()
    incident = Incident.model_validate_json(data)
    source = ReportSource(name=SAMPLE.name, sha256=hashlib.sha256(data).hexdigest())
    return {
        EXAMPLES / "account-takeover.md": make_report(
            incident, ReportFormat.MARKDOWN, source=source
        ),
        EXAMPLES / "account-takeover.html": make_report(incident, ReportFormat.HTML, source=source),
        EXAMPLES / "account-takeover-redacted.md": make_report(
            incident, ReportFormat.MARKDOWN, source=source, redact_ips=True, key=EXAMPLE_KEY
        ),
    }


def demo_image() -> str:
    """Run the demo in a temporary directory and capture its output as SVG."""
    console = Console(
        record=True, width=100, force_terminal=True, color_system="truecolor", file=io.StringIO()
    )
    console.print("[bold green]$[/] prohori demo")
    previous = Path.cwd()
    with tempfile.TemporaryDirectory() as work:
        os.chdir(work)
        try:
            run_demo(
                Path("prohori-demo"),
                seed=1,
                names=list(DEFAULT_SCENARIOS),
                fmt=ReportFormat.HTML,
                console=console,
            )
        finally:
            os.chdir(previous)
    return console.export_svg(title="prohori demo")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="only check the report examples")
    args = parser.parse_args(argv)
    expected = reports()
    stale = [
        p.name
        for p, text in expected.items()
        if not p.is_file() or p.read_text(encoding="utf-8") != text
    ]
    if args.check:
        if stale:
            print(
                f"out of date: {', '.join(stale)}; run scripts/generate_examples.py",
                file=sys.stderr,
            )
            return 1
        return 0
    EXAMPLES.mkdir(parents=True, exist_ok=True)
    for path, text in expected.items():
        path.write_text(text, encoding="utf-8", newline="\n")
    IMAGE.parent.mkdir(parents=True, exist_ok=True)
    svg = "\n".join(line.rstrip() for line in demo_image().splitlines()) + "\n"
    IMAGE.write_text(svg, encoding="utf-8", newline="\n")
    print(f"updated {EXAMPLES} and {IMAGE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
