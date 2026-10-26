# Releasing

Releases are published from GitHub Actions with
[trusted publishing](https://docs.pypi.org/trusted-publishers/): no API token exists anywhere.
The workflow is [`.github/workflows/release.yml`](../.github/workflows/release.yml).

## Steps

1. **Prepare a pull request** that:
   - sets `__version__` in `src/prohori/version.py` (for example `0.2.0`);
   - turns `## [Unreleased]` in `CHANGELOG.md` into `## [0.2.0] - YYYY-MM-DD`, adds a new empty
     `## [Unreleased]` above it and updates the comparison links at the bottom;
   - regenerates what records the version: the sample incident
     (`prohori incidents samples/logs/account-takeover.jsonl -f json`, saved to
     `samples/incidents/`), the golden files (`PROHORI_UPDATE_GOLDEN=1 uv run pytest`) and the
     examples (`uv run python scripts/generate_examples.py`).
2. **Merge it** once CI is green.
3. **Tag the merge commit** on `main` and push the tag:

   ```bash
   git switch main && git pull
   git tag -a v0.2.0 -m "Prohori 0.2.0"
   git push origin v0.2.0
   ```

4. **The workflow then:**
   1. checks that the tag matches the package version and that the changelog has the section;
   2. builds the sdist and wheel and runs `twine check`;
   3. installs the wheel alone in fresh environments on Linux and Windows and runs
      `prohori demo` and `prohori rules test`;
   4. publishes to **TestPyPI**;
   5. **waits for approval** of the `pypi` environment: open the run under *Actions*, review it
      and click *Approve and deploy*;
   6. publishes to **PyPI** (with build attestations);
   7. creates the **GitHub release** with the changelog section as notes and the distributions
      attached;
   8. installs the release from PyPI on Linux and Windows and runs `prohori demo`.

Running the workflow by hand (*Actions > Release > Run workflow*), or on a pull request that
changes packaging, only builds and tests; it never publishes.

## Things to know

- **A version can be published only once.** PyPI and TestPyPI never accept the same version
  twice, even after a deletion. If publishing fails after TestPyPI, fix the problem and release
  the next patch version.
- **Yanking, not deleting:** a broken release is *yanked* on PyPI (it stays installable when pinned
  but is skipped otherwise), and a fixed version follows.
- **One-time setup** (done for this repository): pending publishers on PyPI and TestPyPI for
  project `prohori`, owner `UtshaBasak`, repository `Prohori`, workflow `release.yml`, and GitHub
  environments `testpypi` and `pypi`, the latter with a required reviewer.
