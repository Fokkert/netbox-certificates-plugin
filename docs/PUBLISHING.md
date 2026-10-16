# Publishing releases

The current release version is **1.9.2**. Verify its GitHub Actions publication before installing; never retag or re-upload a published version. For deployment, follow [Upgrade](../UPGRADE.md).

For a future release:

1. Choose a new version and update package/runtime metadata, release checks, README, changelog, and upgrade instructions together.
2. Review and commit the intended changes on `main`.
3. Run `python scripts/release.py` to validate tests and distribution builds.
4. After publication is authorized, run `python scripts/release.py --publish`.
5. Verify that the release workflow and PyPI publication succeed before giving users the new pip install command.

On Windows with this repository's virtual environment, use `.venv/Scripts/python.exe` instead of `python`. The helper atomically pushes `main` and the new version tag; it never overwrites a published tag. GitHub Actions uses PyPI trusted publishing.

```bash
gh run list --workflow release.yml
gh run watch RUN_ID --exit-status
gh release view v1.9.2
```

Replace `RUN_ID` and, for a future release, the tag with the actual values. See [Releasing](RELEASING.md) for prerequisites and helper behavior.

Older GitHub releases preceding v1.9.1 were removed. Older release records/assets were removed at the maintainer's request; Git tags, commit history, migrations, and historical PyPI packages remain. The publishing workflow does not automatically delete previous releases.
