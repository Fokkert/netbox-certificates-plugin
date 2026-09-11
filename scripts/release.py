"""Validate/build locally; --publish atomically pushes main and its version tag."""
import argparse
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1]


def run(*args, capture=False):
    result = subprocess.run(args, cwd=ROOT, check=True, text=True,
                            stdout=subprocess.PIPE if capture else None)
    return result.stdout.strip() if capture else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--publish", action="store_true", help="Push the committed revision and tag to GitHub; triggers PyPI publication.")
    args = parser.parse_args()
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    tag = f"v{version}"
    if args.publish:
        if run("git", "status", "--porcelain", capture=True):
            raise SystemExit("Commit the reviewed changes before publishing. The release script never stages files automatically.")
        if run("git", "branch", "--show-current", capture=True) != "main":
            raise SystemExit("Publish from the reviewed main branch.")
        remote = run("git", "remote", "get-url", "--push", "origin", capture=True)
        if remote not in {"https://github.com/Fokkert/netbox-certificates-plugin.git", "git@github.com:Fokkert/netbox-certificates-plugin.git"}:
            raise SystemExit("Unexpected origin; refusing to publish to a different repository.")
        if run("git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}", capture=True):
            raise SystemExit(f"{tag} is already published. Inspect GitHub Actions instead of republishing it.")
        run("git", "fetch", "origin", "main")
        run("git", "merge-base", "--is-ancestor", "origin/main", "HEAD")
    run(sys.executable, "scripts/check_release_metadata.py")
    run(sys.executable, "-m", "compileall", "-q", "netbox_certificates", "tests")
    run(sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v")
    run("git", "diff", "--check")
    with tempfile.TemporaryDirectory(prefix="nbcert-release-") as output:
        run(sys.executable, "-m", "build", "--no-isolation", "--outdir", output)
        artifacts = [str(path) for path in Path(output).iterdir()]
        run(sys.executable, "-m", "twine", "check", *artifacts)
    if not args.publish:
        print(f"{tag} validated. Nothing pushed. Run with --publish when publication is requested.")
        return
    existing = run("git", "tag", "--list", tag, capture=True)
    if existing:
        if run("git", "rev-parse", f"{tag}^{{commit}}", capture=True) != run("git", "rev-parse", "HEAD", capture=True):
            raise SystemExit("The local release tag points to a different commit. It was not changed.")
    else:
        run("git", "tag", "-a", tag, "-m", f"Release {version}")
    run("git", "push", "--atomic", "origin", "HEAD:refs/heads/main", f"refs/tags/{tag}")
    print(f"Pushed {tag}. GitHub Actions will build, create the release, and publish to PyPI.")
    print("Check completion: gh run list --workflow release.yml")


if __name__ == "__main__":
    main()
