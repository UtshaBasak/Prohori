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
3. **Tag the merge commit** on `main` with a signed tag and push it (one-time set-up in
   [Signing tags](#signing-tags)):

   ```bash
   git switch main && git pull
   git tag -s v0.2.0 -m "Prohori 0.2.0"
   git push origin v0.2.0
   ```

   Only the owner can create `v*` tags (a repository ruleset), and a signed tag shows as
   *Verified* on GitHub, so anyone can tell an official release from a copy.

4. **The workflow then:**
   1. checks that the tag matches the package version and that the changelog has the section;
   2. builds the sdist and wheel and runs `twine check`;
   3. installs the wheel alone in fresh environments on Linux, Windows and macOS and runs
      `prohori demo` (which must finish within a minute) and `prohori rules test`;
   4. signs a provenance attestation for the wheel and sdist (Sigstore, through GitHub's
      attestations) and keeps the bundle as the `provenance` artifact;
   5. publishes to **TestPyPI**;
   6. **waits for approval** of the `pypi` environment: open the run under *Actions*, review it
      and click *Approve and deploy*;
   7. publishes to **PyPI** (with build attestations);
   8. installs the release from PyPI on Linux, Windows and macOS and runs `prohori demo`
      (within a minute);
   9. publishes the Docker image to GitHub Packages as `ghcr.io/utshabasak/prohori:X.Y.Z`,
      `:X.Y` and `:latest`, for linux/amd64 and linux/arm64, with a provenance attestation
      (`gh attestation verify oci://ghcr.io/utshabasak/prohori:X.Y.Z --owner UtshaBasak`).
      Before PyPI, a job builds the image, runs it and checks it holds only the package; pull
      requests that change `pipeline/Dockerfile` run that job too.

5. **Create the GitHub release** from the same files and their signed provenance, with the
   changelog section as notes (`<run-id>` is the release run's id, shown in its URL):

   ```bash
   gh run download <run-id> --name dist --dir dist
   gh run download <run-id> --name provenance --dir dist
   uv run python scripts/release_notes.py 0.2.0 > notes.md
   gh release create v0.2.0 dist/* --title "Prohori 0.2.0" --notes-file notes.md --verify-tag
   ```

   Anyone can then check a downloaded file:
   `gh attestation verify prohori-0.2.0-py3-none-any.whl --owner UtshaBasak`.

   The workflow does not do this itself on purpose: creating a release needs a token that can
   write to the repository, and no job in the release workflow has one.

Running the workflow by hand (*Actions > Release > Run workflow*), or on a pull request that
changes packaging, only builds and tests; it never publishes.

## Verifying a release

Official Prohori releases come only from this repository's release workflow (see
[TRADEMARKS.md](../TRADEMARKS.md) for the official channels). To check that a file really is
one:

```bash
# A wheel, sdist or other file attached to a GitHub release (needs the GitHub CLI):
gh attestation verify prohori-1.1.0-py3-none-any.whl --owner UtshaBasak
# The container image:
gh attestation verify oci://ghcr.io/utshabasak/prohori:1.1.0 --owner UtshaBasak
# The release tag (after git fetch --tags):
git verify-tag v1.1.0
```

Without the GitHub CLI, compare the file's SHA-256 with the one GitHub shows next to the asset
on the release page: `Get-FileHash .\prohori-1.1.0-py3-none-any.whl` in PowerShell, or
`sha256sum prohori-1.1.0-py3-none-any.whl` on Linux and macOS. PyPI shows the same attestation
under the file's *Verified details*.

## Signing tags

Tags are signed with an SSH key (free, no extra tools). One-time set-up on the owner's machine:

1. Create a signing key with a passphrase:
   `ssh-keygen -t ed25519 -C "prohori tag signing" -f "$HOME/.ssh/prohori_signing"`.
2. Add `prohori_signing.pub` on GitHub under *Settings > SSH and GPG keys > New SSH key*, with
   *Key type: Signing Key*.
3. Tell git to use it:

   ```bash
   git config --global gpg.format ssh
   git config --global user.signingkey "$HOME/.ssh/prohori_signing.pub"
   git config --global tag.gpgSign true
   ```

4. Let `git verify-tag` check signatures locally: add a line
   `<your GitHub email> <contents of prohori_signing.pub>` to `~/.ssh/allowed_signers` and run
   `git config --global gpg.ssh.allowedSignersFile "$HOME/.ssh/allowed_signers"`.
5. On Windows, start the OpenSSH agent once (PowerShell as administrator:
   `Set-Service ssh-agent -StartupType Automatic; Start-Service ssh-agent`), then
   `ssh-add "$HOME\.ssh\prohori_signing"` so tagging does not ask for the passphrase every time.

## Things to know

- **A version can be published only once.** PyPI and TestPyPI never accept the same version
  twice, even after a deletion. If publishing fails after TestPyPI, fix the problem and release
  the next patch version.
- **Yanking, not deleting:** a broken release is *yanked* on PyPI (it stays installable when pinned
  but is skipped otherwise), and a fixed version follows.
- **The image's visibility:** a package that is pushed for the first time can be private.
  Make it public once under the package's *Package settings > Change visibility*; later
  versions keep that setting.
- **One-time setup** (done for this repository): pending publishers on PyPI and TestPyPI for
  project `prohori`, owner `UtshaBasak`, repository `Prohori`, workflow `release.yml`, and GitHub
  environments `testpypi` and `pypi`, the latter with a required reviewer.
