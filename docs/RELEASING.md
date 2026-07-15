# Releasing to PyPI

The repository uses PyPI Trusted Publishing. No long-lived API token is stored
in GitHub.

## One-time owner setup

1. Confirm that the `monna-adip` project name is available on PyPI.
2. Create or reserve the project under the intended PyPI owner.
3. Add a trusted publisher for:
   - GitHub owner: `emanalshazly`
   - Repository: `monna-adip`
   - Workflow: `publish.yml`
   - Environment: `pypi`
4. Create the protected GitHub environment named `pypi`.
5. Require manual approval on that environment if release review is desired.

## Release process

1. Update `src/monna_adip/version.py`, `pyproject.toml`, `CITATION.cff`, and the changelog.
2. Merge a green release PR to `main`.
3. Create a GitHub release whose tag starts with `v`, such as `v0.2.0`.
4. The workflow builds both sdist and wheel, then publishes through OIDC.
5. Verify installation in a clean environment before announcing the release.

Publishing remains blocked until the PyPI trusted publisher and GitHub
environment are configured by the repository owner.
