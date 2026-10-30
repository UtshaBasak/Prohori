# Data

Public datasets live here and are **never committed**: everything in this directory except this
file is git-ignored. See [docs/DATASETS.md](../docs/DATASETS.md) for licences and details.

| Path | Contents |
|------|----------|
| `raw/<dataset>/` | The files as published: `unsw-nb15/` (two CSVs you download by hand), `cicids2017/` (the archive and five CSVs from `fetch`) |
| `processed/<dataset>/` | Parquet copies of the CSVs, keyed by each raw file's SHA-256; safe to delete |

```bash
uv run python scripts/download_datasets.py list               # what to get and how
uv run python scripts/download_datasets.py fetch cicids2017   # about 330 MB, then 1.1 GB of CSV
uv run python scripts/download_datasets.py verify             # sizes and checksums
```
