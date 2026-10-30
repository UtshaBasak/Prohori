"""scripts/download_datasets.py: listing, verifying, safe fetching, preparing. No network."""

import hashlib
import io
import json
import subprocess
import sys
import zipfile
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from prohori.ml import registry
from prohori.ml.registry import CICIDS2017, Archive, DataFile
from scripts import download_datasets

ROOT = Path(__file__).resolve().parents[3]


def test_help_documents_every_dataset(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as done:
        download_datasets.main(["--help"])
    assert done.value.code == 0
    out = capsys.readouterr().out
    for name in registry.DATASETS:
        assert name in out
    assert "licence:" in out
    assert "manual download" in out


def test_list_shows_licence_citation_and_steps(capsys: pytest.CaptureFixture[str]) -> None:
    assert download_datasets.main(["list"]) == 0
    out = capsys.readouterr().out
    for dataset in registry.DATASETS.values():
        assert dataset.citation in out
        assert dataset.licence in out
        assert dataset.manual_steps[0] in out


def test_verify(data_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert download_datasets.main(["--data-dir", str(data_dir), "verify", "unsw-nb15"]) == 0
    out = capsys.readouterr().out
    assert out.count("UNPINNED") == 2
    # The fixture days are not the real files: their sizes do not match the pins.
    assert download_datasets.main(["--data-dir", str(data_dir), "verify", "cicids2017"]) == 1
    out = capsys.readouterr().out
    assert "BAD" in out
    assert "To get cicids2017" in out
    (data_dir / "raw" / "unsw-nb15" / "UNSW_NB15_testing-set.csv").unlink()
    assert download_datasets.main(["--data-dir", str(data_dir), "verify"]) == 1
    assert "MISSING" in capsys.readouterr().out


def test_verify_pinned_files(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    folder = tmp_path / "raw" / "cicids2017"
    folder.mkdir(parents=True)
    (folder / "a.csv").write_bytes(b"abc")
    good = DataFile("a.csv", size=3, sha256=hashlib.sha256(b"abc").hexdigest())
    dataset = replace(CICIDS2017, files=(good,))
    assert download_datasets.verify(dataset, tmp_path)
    assert not download_datasets.verify(
        replace(dataset, files=(replace(good, sha256="0" * 64),)), tmp_path
    )


# --------------------------------------------------------------------------- fetch


def _zip(members: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for name, data in members.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def _dataset(
    body: bytes, members: dict[str, bytes], url: str = "https://example.org/d.zip"
) -> registry.Dataset:
    files = tuple(
        DataFile(n, size=len(d), sha256=hashlib.sha256(d).hexdigest()) for n, d in members.items()
    )
    archive = Archive("d.zip", url, size=len(body), sha256=hashlib.sha256(body).hexdigest())
    return replace(CICIDS2017, files=files, archive=archive)


def _client(body: bytes, status: int = 200) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url == httpx.URL("https://example.org/d.zip")
        return httpx.Response(status, content=body)

    return httpx.Client(transport=httpx.MockTransport(handler))


Install = Callable[[registry.Dataset], None]


@pytest.fixture
def use(monkeypatch: pytest.MonkeyPatch) -> Install:
    """Replace a registry entry for one test."""

    def install(dataset: registry.Dataset) -> None:
        monkeypatch.setitem(registry.DATASETS, dataset.name, dataset)

    return install


MEMBERS = {"monday.csv": b"id,label\n1,BENIGN\n", "friday.csv": b"id,label\n2,DDoS\n"}


def test_fetch_downloads_verifies_and_extracts(tmp_path: Path, use: Install) -> None:
    body = _zip(MEMBERS)
    use(_dataset(body, MEMBERS))
    args = ["--data-dir", str(tmp_path), "fetch", "cicids2017"]
    assert download_datasets.main(args, client=_client(body)) == 0
    folder = tmp_path / "raw" / "cicids2017"
    assert (folder / "friday.csv").read_bytes() == MEMBERS["friday.csv"]
    assert (folder / "d.zip").read_bytes() == body
    assert not list(folder.glob("*.part"))
    # Run again: the archive on disk is checked and reused, nothing is downloaded.
    assert download_datasets.main(args, client=_client(b"", status=500)) == 0


def test_fetch_rejects_a_wrong_checksum(
    tmp_path: Path, use: Install, capsys: pytest.CaptureFixture[str]
) -> None:
    body = _zip(MEMBERS)
    use(_dataset(body, MEMBERS))
    tampered = body[:-1] + bytes([body[-1] ^ 1])
    args = ["--data-dir", str(tmp_path), "fetch", "cicids2017"]
    assert download_datasets.main(args, client=_client(tampered)) == 1
    assert "does not match the pinned checksum" in capsys.readouterr().err
    assert list((tmp_path / "raw" / "cicids2017").iterdir()) == []


def test_fetch_stops_at_the_expected_size(
    tmp_path: Path, use: Install, capsys: pytest.CaptureFixture[str]
) -> None:
    body = _zip(MEMBERS)
    use(_dataset(body, MEMBERS))
    args = ["--data-dir", str(tmp_path), "fetch", "cicids2017"]
    assert download_datasets.main(args, client=_client(body + b"x" * 10)) == 1
    assert "larger than the expected" in capsys.readouterr().err
    assert list((tmp_path / "raw" / "cicids2017").iterdir()) == []


def test_fetch_reports_http_errors(
    tmp_path: Path, use: Install, capsys: pytest.CaptureFixture[str]
) -> None:
    body = _zip(MEMBERS)
    use(_dataset(body, MEMBERS))
    args = ["--data-dir", str(tmp_path), "fetch", "cicids2017"]
    assert download_datasets.main(args, client=_client(b"gone", status=404)) == 1
    assert "HTTP 404" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("members", "error"),
    [
        ({"../evil.csv": b"x", "monday.csv": b"a"}, "unexpected members"),
        ({"monday.csv": b"a", "friday.csv": b"b", "extra.csv": b"c"}, "unexpected members"),
        ({"monday.csv": b"a" * 50, "friday.csv": b"b"}, "would be 50 bytes"),
    ],
)
def test_extract_refuses_unsafe_archives(
    tmp_path: Path, members: dict[str, bytes], error: str
) -> None:
    dataset = _dataset(b"", {"monday.csv": b"a", "friday.csv": b"b"})
    path = tmp_path / "d.zip"
    path.write_bytes(_zip(members))
    with pytest.raises(download_datasets.FetchError, match=error):
        download_datasets.extract(dataset, path, tmp_path)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["d.zip"]


def test_extract_refuses_member_paths(tmp_path: Path) -> None:
    dataset = _dataset(b"", {"sub/monday.csv": b"a"})
    path = tmp_path / "d.zip"
    path.write_bytes(_zip({"sub/monday.csv": b"a"}))
    with pytest.raises(download_datasets.FetchError, match="with a path"):
        download_datasets.extract(dataset, path, tmp_path)


def test_fetch_of_a_manual_dataset_prints_the_steps(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert not download_datasets.fetch(registry.UNSW_NB15, tmp_path)
    assert "SharePoint" in capsys.readouterr().out
    with pytest.raises(SystemExit):
        download_datasets.main(["fetch", "unsw-nb15"])  # not a choice


# --------------------------------------------------------------------------- prepare


def test_prepare_prints_the_report(data_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = ["--data-dir", str(data_dir), "prepare", "unsw-nb15", "--seed", "1"]
    assert download_datasets.main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["overlap_removed"]["test"] == 2
    assert report["seed"] == 1


def test_prepare_without_the_files(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert download_datasets.main(["--data-dir", str(tmp_path), "prepare", "cicids2017"]) == 1
    assert "fetch cicids2017" in capsys.readouterr().err


# --------------------------------------------------------------------------- base install


def test_base_install_does_not_need_the_ml_extra() -> None:
    """With pandas, scikit-learn and pyarrow unavailable, everything but ML still imports."""
    code = """
import sys
for name in ("pandas", "sklearn", "pyarrow", "numpy"):
    sys.modules[name] = None
import prohori, prohori.cli, prohori.ml, prohori.ml.registry
from prohori.ml import MissingExtraError
for module in ("prohori.ml.datasets", "prohori.ml.cleaning"):
    try:
        __import__(module)
    except MissingExtraError as exc:
        print(exc)
    else:
        raise SystemExit(module + " imported without its dependencies")
from scripts import download_datasets
assert download_datasets.main(["list"]) == 0
"""
    done = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert done.returncode == 0, done.stderr
    assert "needs the 'ml' extra: pip install 'prohori[ml]'" in done.stdout


def test_importing_the_cli_does_not_load_pandas() -> None:
    code = "import sys, prohori.cli; print(sorted({'pandas', 'sklearn'} & set(sys.modules)))"
    done = subprocess.run(  # noqa: S603 - fixed arguments
        [sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True, check=False
    )
    assert done.stdout.strip() == "[]", done.stderr
