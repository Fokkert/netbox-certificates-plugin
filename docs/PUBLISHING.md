# Publishing 1.1.2

The existing tag-triggered GitHub Action builds the distribution, creates the GitHub Release, and publishes the package through PyPI trusted publishing. No new credentials are needed for this revision.

After reviewing the changes, commit them on `main` and run the existing publishing helper:

```bash
git add netbox_certificates tests scripts docs README.md UPGRADE.md VALIDATION.md CHANGELOG.md pyproject.toml netbox-plugin.yaml
git commit -m "Release 1.1.2: group forms, bundle names, and health findings"
python scripts/release.py --publish
```

On Windows with this repository's virtual environment, use `.venv/Scripts/python.exe` instead of `python`. The helper checks the package version, tests, and build, then atomically pushes `main` and `v1.1.2`. It does not force or overwrite a published tag.

```bash
gh run list --workflow release.yml
gh run watch RUN_ID --exit-status
gh release view v1.1.2
```

Use the actual run ID returned by the first command. Check that the PyPI job completed before installing `netbox-certificates-plugin==1.1.2` on the VM. See [Releasing](RELEASING.md) for the helper behavior and [Upgrade](../UPGRADE.md) for Linux installation commands.
