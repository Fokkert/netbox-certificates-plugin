# Publishing a release

GitHub Actions already creates a GitHub Release and publishes the same wheel/sdist to PyPI when a `v*` tag is pushed. Version 1.3.3 preserves that trusted-publisher workflow and installs the behavioral test dependencies before release builds.

The repository's `scripts/release.py` makes the local operation repeatable:

```bash
python -m pip install -r tests/requirements.txt
python -m pip install 'setuptools>=77' wheel build twine
python scripts/release.py
```

That command checks metadata, runs tests, compiles sources, checks whitespace, builds in an isolated temporary output directory, and checks distribution metadata. It does not push.

When the user requests publication, the agent can review and commit the intended changes, then run:

```bash
python scripts/release.py --publish
```

Publication requires a clean, reviewed main branch, the expected GitHub origin, an unused version tag, and a local HEAD that includes current origin/main. The script creates an annotated tag and atomically pushes main and the tag without forcing either ref. It never stages files, bumps versions, rewrites a published tag, or bypasses GitHub/PyPI approval settings.

Monitor the result:

```bash
gh run list --workflow release.yml
gh run watch RUN_ID --exit-status
gh release view v1.3.3
```

Replace `RUN_ID` with the actual run ID. A pushed tag is not proof of successful PyPI publication. Inspect the workflow result before giving users the PyPI install command. A failed publish can be rerun in GitHub Actions after correcting the cause; do not overwrite a published package version.

No GitHub or PyPI credentials are stored by this helper. It uses the existing Git authentication and GitHub Actions trusted publisher.
