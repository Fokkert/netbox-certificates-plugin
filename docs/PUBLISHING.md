# Publishing 1.0.1

## Preconditions

Before publishing:

1. apply the supplied update to a clean 0.5.0 clone;
2. allow the updater's static tests/compile checks to complete;
3. review `git status`;
4. push `main`;
5. let GitHub Actions complete successfully.

## Commit and push

```powershell
cd "$HOME\Desktop\test\netbox-certificates-plugin"

git add -A
git commit -m "feat: release certificate management 1.0"
git push origin main
```

## Tag

After the main-branch workflow succeeds:

```powershell
git tag -a v1.0.1 -m "NetBox Certificates Plugin 1.0.1"
git push origin v1.0.1
```

The repository's release workflow should build/validate the wheel and source distribution, create/update the GitHub Release and publish to PyPI according to its existing trusted-publishing configuration.

Do not publish a second manually-built distribution with different bytes under the same version.

## PyPI verification

After publication:

```bash
python -m pip index versions netbox-certificates-plugin \
  --index-url https://pypi.org/simple \
  --no-cache-dir
```

Confirm `1.0.1` is visible before changing production `local_requirements.txt`.
