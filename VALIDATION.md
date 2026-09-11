# Validation for 1.1.0

## Completed in the Windows development workspace

- Verified local HEAD matches GitHub main and the v1.0.5 release baseline.
- 53 standalone tests passed under Python 3.12 and Django 5.2.
- Real cryptographic PFX round trips: encrypted, unencrypted opt-in, incorrect password, mismatched key, and chain selection.
- Real Django form validation, template rendering with an isolated layout, and route/action consistency checks.
- Service endpoint inference and explicit overrides, actual certificate validity/SAN field handling, SMTP TLS contexts, alert timing, and recovery deduplication.
- Python compilation, release metadata checks, repository source scan, and diff whitespace checks.
- Wheel and sdist build; distribution metadata checked with twine.

Standalone tests deliberately isolate functions/forms from the NetBox application. Template tests use a minimal parent layout; they are not a full browser test or a substitute for the NetBox runtime tests below.

## Standalone commands

```bash
python -m pip install -r tests/requirements.txt
python -m pip install 'setuptools>=77' wheel build twine
python scripts/release.py
```

The helper validates and builds without pushing unless `--publish` is explicitly supplied.

## NetBox runtime validation still required

This workspace does not have a running NetBox/PostgreSQL/Redis test stack. No claim of a completed live VM integration test is made.

On a disposable NetBox 4.5.9/4.5.10 test installation with this plugin installed:

```bash
python manage.py check
python manage.py migrate --check
python manage.py makemigrations --check --dry-run netbox_certificates
python manage.py test netbox_certificates.tests
```

The integration suite exercises populated health/detail/edit pages, the old-dashboard redirect, folder hierarchy rendering, service creation with endpoint inference, alert configuration, and denial of unprivileged settings access. Django's test runner requires permission to create a test database; do not point an ad hoc test setup at production data.

Also verify on the test VM:

1. Existing encrypted material remains decryptable using the unchanged Fernet key.
2. Single and bulk bundle downloads contain only the selected material, and PFX files open with the chosen password mode.
3. Existing alert rules are visible under additional rules; save the new settings, then explicitly test email/webhook delivery.
4. NetBox's RQ worker processes the periodic health/alert job.
5. Verify constrained non-admin users only see permitted certificate/group/finding data.

See UPGRADE.md for install, backup, verification, and rollback commands.
