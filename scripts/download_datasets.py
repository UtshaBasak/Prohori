"""Get, verify and prepare the public flow datasets used by the ML detectors.

Nothing happens unless you run a command, and only ``fetch`` uses the network. Files go to
``data/raw/<dataset>/``, which git ignores; see docs/DATASETS.md for licences and citations.

    uv run python scripts/download_datasets.py list
    uv run python scripts/download_datasets.py fetch cicids2017
    uv run python scripts/download_datasets.py verify [DATASET]
    uv run python scripts/download_datasets.py prepare DATASET [--sample 0.1]
"""

import argparse
import hashlib
import json
import sys
import textwrap
import zipfile
from pathlib import Path, PurePosixPath

import httpx

from prohori.ml import MissingExtraError
from prohori.ml.registry import DATASETS, Dataset, get_dataset
from prohori.version import __version__

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DATA_DIR = ROOT / "data"
BLOCK = 1 << 20
TIMEOUT = httpx.Timeout(60.0, connect=15.0)


class FetchError(RuntimeError):
    """A download or an archive failed a check; nothing was kept."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while block := handle.read(BLOCK):
            digest.update(block)
    return digest.hexdigest()


def _epilog() -> str:
    lines = ["datasets:"]
    for d in DATASETS.values():
        how = "fetch downloads it" if d.archive else "manual download (see 'list')"
        lines.append(f"  {d.name:<12} {d.title}; {how}")
        lines += textwrap.wrap(
            f"licence: {d.licence}", 90, initial_indent=" " * 15, subsequent_indent=" " * 15
        )
    return "\n".join(lines)


def describe(dataset: Dataset) -> str:
    lines = [
        f"{dataset.name}: {dataset.title}",
        f"  version:  {dataset.version}",
        f"  homepage: {dataset.homepage}",
        f"  licence:  {dataset.licence}",
        f"  cite:     {dataset.citation}",
        "  files:",
    ]
    for f in dataset.files:
        extra = [f"{f.split} split"] if f.split else []
        extra += [f"{f.rows:,} rows"] if f.rows else []
        extra += [f"{f.size:,} bytes"] if f.size else []
        extra.append("sha256 pinned" if f.sha256 else "sha256 not pinned yet")
        lines.append(f"    {f.name} ({', '.join(extra)})")
    if dataset.archive:
        lines.append(f"  archive:  {dataset.archive.url} ({dataset.archive.size:,} bytes)")
    lines.append("  how to get it:")
    lines += [f"    {i}. {step}" for i, step in enumerate(dataset.manual_steps, 1)]
    lines += [f"  note: {note}" for note in dataset.notes]
    return "\n".join(lines)


def verify(dataset: Dataset, data_dir: Path) -> bool:
    """Check every file's size and SHA-256; print what was found. True when all pass."""
    folder = data_dir / "raw" / dataset.name
    ok = True
    for f in dataset.files:
        path = folder / f.name
        if not path.is_file():
            print(f"MISSING  {path}")
            ok = False
            continue
        size = path.stat().st_size
        if f.size is not None and size != f.size:
            print(f"BAD      {path}: {size:,} bytes, expected {f.size:,}")
            ok = False
            continue
        digest = _sha256(path)
        if f.sha256 is None:
            print(f"UNPINNED {path}: sha256 {digest} (not pinned yet; compare with a colleague)")
        elif digest != f.sha256:
            print(f"BAD      {path}: sha256 {digest}, expected {f.sha256}")
            ok = False
        else:
            print(f"OK       {path}")
    if not ok:
        print(f"\nTo get {dataset.name}:")
        for i, step in enumerate(dataset.manual_steps, 1):
            print(f"  {i}. {step}")
    return ok


def download(dataset: Dataset, target: Path, client: httpx.Client) -> None:
    """Stream the dataset's archive to ``target``, checking size and SHA-256 before keeping it."""
    archive = dataset.archive
    if archive is None:
        msg = f"{dataset.name} has no direct download; see 'list' for the manual steps"
        raise FetchError(msg)
    partial = target.with_name(target.name + ".part")
    digest = hashlib.sha256()
    received = 0
    try:
        with client.stream("GET", archive.url) as response:
            if response.status_code != httpx.codes.OK:
                msg = f"{archive.url} answered HTTP {response.status_code}"
                raise FetchError(msg)
            with partial.open("wb") as handle:
                for block in response.iter_bytes(BLOCK):
                    received += len(block)
                    if received > archive.size:
                        msg = f"{archive.name} is larger than the expected {archive.size:,} bytes"
                        raise FetchError(msg)
                    digest.update(block)
                    handle.write(block)
                    print(f"\r  {received / 1e6:,.0f} / {archive.size / 1e6:,.0f} MB", end="")
        print()
        if received != archive.size or digest.hexdigest() != archive.sha256:
            msg = (
                f"{archive.name} does not match the pinned checksum "
                f"({received:,} bytes, sha256 {digest.hexdigest()})"
            )
            raise FetchError(msg)
        partial.replace(target)
    finally:
        partial.unlink(missing_ok=True)


def check_archive(dataset: Dataset, path: Path) -> None:
    archive = dataset.archive
    if archive is None:
        msg = f"{dataset.name} has no archive"
        raise FetchError(msg)
    if path.stat().st_size != archive.size or _sha256(path) != archive.sha256:
        msg = f"{path} does not match the pinned size and sha256; delete it and fetch again"
        raise FetchError(msg)


def extract(dataset: Dataset, path: Path, folder: Path) -> list[Path]:
    """Extract the expected members only: no other names, no paths, no size above the pin."""
    expected = {f.name: f for f in dataset.files}
    written: list[Path] = []
    with zipfile.ZipFile(path) as archive:
        members = archive.infolist()
        names = [m.filename for m in members if not m.is_dir()]
        unexpected = sorted(set(names) - set(expected))
        if unexpected or len(names) != len(set(names)):
            msg = f"{path.name} holds unexpected members: {unexpected or 'duplicates'}"
            raise FetchError(msg)
        for member in members:
            if member.is_dir():
                continue
            name = member.filename
            if PurePosixPath(name).name != name or "\\" in name:
                msg = f"{path.name}: refusing member with a path: {name!r}"
                raise FetchError(msg)
            limit = expected[name].size
            if limit is not None and member.file_size != limit:
                msg = f"{name} would be {member.file_size:,} bytes, expected {limit:,}"
                raise FetchError(msg)
            target = folder / name
            partial = target.with_name(name + ".part")
            copied = 0
            try:
                with archive.open(member) as source, partial.open("wb") as handle:
                    while block := source.read(BLOCK):
                        copied += len(block)
                        if limit is not None and copied > limit:
                            msg = f"{name} is larger than its declared size"
                            raise FetchError(msg)
                        handle.write(block)
                partial.replace(target)
            finally:
                partial.unlink(missing_ok=True)
            written.append(target)
    return written


def fetch(dataset: Dataset, data_dir: Path, client: httpx.Client | None = None) -> bool:
    if dataset.archive is None:
        print(f"{dataset.name} cannot be downloaded by this script.\n\n{describe(dataset)}")
        return False
    folder = data_dir / "raw" / dataset.name
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / dataset.archive.name
    print(f"{dataset.title}\n  licence: {dataset.licence}\n  cite: {dataset.citation}")
    try:
        if path.is_file():
            print(f"using {path}")
            check_archive(dataset, path)
        else:
            print(f"downloading {dataset.archive.url}")
            own = client is None
            client = client or httpx.Client(
                timeout=TIMEOUT,
                follow_redirects=False,
                headers={"User-Agent": f"prohori/{__version__}"},
            )
            try:
                download(dataset, path, client)
            finally:
                if own:
                    client.close()
        extract(dataset, path, folder)
    except (FetchError, httpx.HTTPError, zipfile.BadZipFile) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return False
    return verify(dataset, data_dir)


def prepare(dataset: Dataset, data_dir: Path, args: argparse.Namespace) -> int:
    try:
        from prohori.ml.cleaning import prepare as prepare_dataset
        from prohori.ml.datasets import DatasetMissingError
    except MissingExtraError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        prepared = prepare_dataset(
            dataset, data_dir, seed=args.seed, sample=args.sample, drop_suspect=args.drop_suspect
        )
    except DatasetMissingError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(prepared.report.to_dict(), indent=2))
    return 0


def main(argv: list[str] | None = None, client: httpx.Client | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        epilog=_epilog(),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="default: data/")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list", help="describe every dataset: files, licence, how to get it")
    fetch_parser = commands.add_parser("fetch", help="download, verify and extract a dataset")
    fetch_parser.add_argument(
        "dataset", choices=sorted(d for d, s in DATASETS.items() if s.archive)
    )
    verify_parser = commands.add_parser("verify", help="check sizes and checksums of the files")
    verify_parser.add_argument("dataset", nargs="?", choices=sorted(DATASETS))
    prepare_parser = commands.add_parser(
        "prepare", help="clean and split a dataset (needs the ml extra) and print the report"
    )
    prepare_parser.add_argument("dataset", choices=sorted(DATASETS))
    prepare_parser.add_argument("--seed", type=int, default=0)
    prepare_parser.add_argument("--sample", type=float, help="fraction of rows, e.g. 0.1")
    prepare_parser.add_argument("--drop-suspect", action="store_true", help="drop suspect columns")
    args = parser.parse_args(argv)

    if args.command == "list":
        print("\n\n".join(describe(d) for d in DATASETS.values()))
        return 0
    if args.command == "fetch":
        return 0 if fetch(get_dataset(args.dataset), args.data_dir, client) else 1
    if args.command == "verify":
        names = [args.dataset] if args.dataset else list(DATASETS)
        results = [verify(get_dataset(n), args.data_dir) for n in names]
        return 0 if all(results) else 1
    return prepare(get_dataset(args.dataset), args.data_dir, args)


if __name__ == "__main__":
    raise SystemExit(main())
