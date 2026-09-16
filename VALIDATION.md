# Validation for 1.2.0

## Completed in the Windows development workspace

- Started from clean v1.1.2 commit `a67fbed`; GitHub main was checked against the same commit and the v1.2.0 tag was unused.
- 103 standalone tests passed under Python 3.12 and Django 5.2.
- Release metadata, compilation, whitespace checks, wheel/sdist builds, and `twine check` passed. Both distributions include migration 0022, the new API/workflow modules, Group stylesheet, export templates, and documentation in the source distribution.
- Complete-module undefined-name checks and URL-to-view symbol checks cover failures that isolated function tests cannot detect.
- Real cryptography tests sign and verify CSRs with existing RSA, EC, and Ed25519 keys; malformed SAN/subject/usage inputs and tampered CSR signatures are rejected.
- Alert form and shared validation checks cover invalid email addresses, hostnames, port boundaries, endpoint URLs, headers, and global certificate settings. Explicit `{}` clears headers while blank preserves them.
- Import tests parse mixed PEM/PFX, nested archives, unusual filenames, and 1,001 certificate files. Invalid archive members, traversal paths, limits, and metadata-only input are rejected.
- Mixed inventory ZIP output is re-parsed and its checksums and unique member paths verified.
- Existing tests for CA-only imports, Group editors, permission scopes, calendar-month alerts, certificate-named bundles/PFX, empty exports, and linked Health findings continue to pass.

Standalone tests isolate functions/forms from NetBox's PostgreSQL/Redis application. They do not establish that every live button and deployment-specific integration has been exercised.

## Release checks

```bash
python -m pip install -r tests/requirements.txt
python -m pip install 'setuptools>=77' wheel build twine
python scripts/release.py
```

The helper checks release metadata, compilation, standalone tests, whitespace, wheel/sdist builds, and distribution metadata. It pushes only with `--publish` after a clean commit.

## NetBox runtime verification

This workspace has no running NetBox/PostgreSQL/Redis stack, and no live VM test was performed. As requested, deployment testing happens after pip installation on the user's VM.

The optional integration suite includes mixed-import database deduplication/relationships, transaction rollback, CSR generation with an existing key, empty exports, retired policy redirects, Group creation/editing, finding links, Services, and restricted alert settings. Run it only on a disposable test database:

```bash
python manage.py check
python manage.py migrate --check
python manage.py makemigrations --check --dry-run netbox_certificates
python manage.py test netbox_certificates.tests
```

After deployment, review migrated global checks and alert scopes, confirm stored secrets remain decryptable, test SMTP/webhook samples, inspect Group hierarchy and constrained-user permissions, import/export a representative mixed batch, and confirm the worker runs scheduled jobs. See [Upgrade](UPGRADE.md) for pip installation and rollback instructions.
