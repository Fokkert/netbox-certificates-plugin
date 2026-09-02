# Publishing to GitHub and PyPI

This document is the maintainer release runbook for NetBox Certificates Plugin.

## 1. Choose the public repository identity

The intended repository name is:

```text
netbox-certificates-plugin
```

Before the first public release, replace **every** occurrence of:

```text
Fokkert
```

with the real GitHub user/organization that will own the repository.

Run:

```bash
python scripts/check_release_metadata.py
```

The check intentionally fails while the placeholder remains.

## 2. Check the PyPI distribution name

The intended distribution name is:

```text
netbox-certificates-plugin
```

PyPI project names are globally unique. Check the live PyPI project page immediately before first publication. If the name has been claimed, change only the **distribution name** in `pyproject.toml` and the release/install documentation; the NetBox plugin import module can remain `netbox_certificates`.

There is an existing GitHub project (`NetworkSeb/netbox-certificates`) using the same Python import module `netbox_certificates`. The projects cannot safely coexist in one Python environment. This is documented in the README.

## 3. Create the GitHub repository

With GitHub CLI authenticated:

```bash
git init -b main
git add .
git commit -m "Initial public release preparation for 0.4.11

AI-Assisted-by: ChatGPT (OpenAI)"

gh repo create Fokkert/netbox-certificates-plugin \
  --public \
  --source=. \
  --remote=origin \
  --push
```

Or create an empty repository in the GitHub UI and add it as `origin` manually.

Recommended repository topics:

```text
netbox netbox-plugin x509 pki certificates csr pkcs12 django ai-assisted-development
```

## 4. ChatGPT/OpenAI attribution

Do **not** fabricate a GitHub co-author email for ChatGPT. GitHub counts a `Co-authored-by:` trailer as a contribution only when the email is associated with a real GitHub account.

This repository instead uses four explicit disclosure surfaces:

1. README disclosure near the top.
2. `AI_ASSISTANCE.md` describing the role of AI and human responsibility.
3. `NOTICE` attribution that downstream Apache-2.0 distributions must preserve when applicable.
4. Optional custom commit trailer:

```text
AI-Assisted-by: ChatGPT (OpenAI)
```

That trailer is human-readable metadata; it is intentionally **not** a fake GitHub co-author identity.

Do not imply that OpenAI sponsors, endorses, owns, or maintains the project.

## 5. License

The repository uses **Apache License 2.0 + NOTICE**.

This is a good fit for a NetBox plugin because it is permissive and compatible with the wider NetBox ecosystem while retaining license/NOTICE attribution obligations and requiring prominent notices for modified files when distributing derivatives.

If you wanted file-level copyleft instead, MPL-2.0 would be a stronger alternative, but switching licenses after public contributions begin can become complicated. Decide before accepting outside contributions.

## 6. Local build verification

Use a clean Python virtual environment separate from production NetBox:

```bash
python3 -m venv .venv-build
source .venv-build/bin/activate
python -m pip install --upgrade pip build twine

python scripts/check_release_metadata.py
python -m unittest discover -s tests -v
python -m compileall -q netbox_certificates
rm -rf dist build *.egg-info
python -m build
python -m twine check dist/*
```

You should get both a wheel and source distribution for version 0.4.11.

## 7. Configure TestPyPI Trusted Publishing

Create/configure the TestPyPI project and add a GitHub Trusted Publisher using:

- GitHub owner: your repository owner
- Repository: `netbox-certificates-plugin`
- Workflow filename: `testpypi.yml`
- Environment: `testpypi`

The workflow in `.github/workflows/testpypi.yml` uses OIDC. It does not require a long-lived PyPI API token in GitHub Secrets.

In GitHub, create the environment **testpypi**. Optionally require maintainer approval for deployments.

Trigger **Actions → Publish to TestPyPI → Run workflow**.

## 8. Test the TestPyPI artifact

For a metadata/download test in an isolated environment:

```bash
python3 -m venv /tmp/nbcert-testpypi
source /tmp/nbcert-testpypi/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography
python -m pip install --no-deps \
  --index-url https://test.pypi.org/simple/ \
  netbox-certificates-plugin==0.4.11
python -m pip show netbox-certificates-plugin
```

Do not import the plugin outside a NetBox environment as a runtime compatibility test; it imports NetBox APIs by design.

## 9. Configure production PyPI Trusted Publishing

On PyPI, create a Trusted Publisher for:

- GitHub owner: your repository owner
- Repository: `netbox-certificates-plugin`
- Workflow filename: `release.yml`
- Environment: `pypi`

Create a protected GitHub environment named **pypi**. Maintainer approval is strongly recommended.

The production workflow triggers only when a GitHub Release is published.

## 10. Create the production release

Make sure the working tree is clean and all checks pass:

```bash
python scripts/check_release_metadata.py
python -m unittest discover -s tests -v
python -m build
python -m twine check dist/*
```

Commit and push any final release changes, then create an annotated tag:

```bash
git tag -a v0.4.11 -m "NetBox Certificates Plugin 0.4.11"
git push origin v0.4.11
```

Create the GitHub Release from that tag, either in the UI or with GitHub CLI:

```bash
gh release create v0.4.11 \
  --verify-tag \
  --title "NetBox Certificates Plugin 0.4.11" \
  --notes-file CHANGELOG.md
```

Publishing the release triggers `.github/workflows/release.yml`, which checks metadata/tag/version consistency, runs tests, builds wheel + sdist, validates them, attaches them to GitHub, and publishes the exact artifacts to PyPI using OIDC Trusted Publishing.

## 11. Verify production publication

Verify all three identities match:

```text
Git tag:       v0.4.11
PluginConfig:  0.4.11
PyPI version:  0.4.11
```

Then validate the published artifact in staging/production using `docs/UNINSTALL.md` and the README.

## 12. Future release checklist

For every version:

1. Update `netbox_certificates/__init__.py` version and compatibility gate if required.
2. Update `pyproject.toml` version.
3. Update `CHANGELOG.md`, `COMPATIBILITY.md`, `UPGRADE.md`, and validation evidence.
4. If NetBox minor-version support changes, run a fresh live test matrix before widening `min_version`/`max_version`.
5. Run tests/build/twine checks.
6. Publish to TestPyPI first for packaging changes.
7. Tag exactly `v<version>`.
8. Publish the GitHub Release and approve the `pypi` environment deployment.
9. Verify PyPI installation from a clean environment.
10. Never reuse/re-upload a PyPI version. Fixes get a new version.
