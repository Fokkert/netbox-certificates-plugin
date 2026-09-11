# Validation for 1.1.2

## Completed in the Windows development workspace

- Started from the clean v1.1.1 release commit `8e10141`; prepared v1.1.2 without pushing or tagging.
- 85 standalone tests passed under Python 3.12 and Django 5.2.
- Group add/edit constructor regression executes the production import and checks Service choices, selected membership, hierarchy exclusions, and permission scoping.
- Single UI and API ZIP/TAR exports use certificate-named archives and PFX files. Bulk exports retain both bundles when certificate names collide; manifests match archive contents and checksums.
- Filename handling covers paths, control characters, Unicode, long names, reserved filenames, and case-insensitive collisions.
- Finding links hide inaccessible or missing objects and escape names. Detail context and populated Health templates show readable evidence, including zero/negative values.
- CSR plural normalization and retained SMTP/webhook sample buttons checked.
- Existing CA-only validation, empty exports, calendar-month alert defaults, scoped permissions, Service form behavior, and cryptographic PFX round-trip regressions still pass.
- Python compilation, release metadata checks, and diff whitespace checks pass.

Standalone tests deliberately isolate functions/forms from the NetBox application. Template tests use a minimal parent layout; they are not a full browser test or a substitute for the NetBox runtime tests below.

## Standalone commands

```bash
python -m pip install -r tests/requirements.txt
python -m pip install 'setuptools>=77' wheel build twine
python scripts/release.py
```

The helper validates and builds without pushing unless `--publish` is explicitly supplied.

## NetBox runtime verification

This workspace does not have a running NetBox/PostgreSQL/Redis test stack. No claim of a completed live VM integration test is made.

The user will verify behavior after installation on the VM. Optional full integration commands for a disposable NetBox 4.5.9/4.5.10 installation are:

```bash
python manage.py check
python manage.py migrate --check
python manage.py makemigrations --check --dry-run netbox_certificates
python manage.py test netbox_certificates.tests
```

The optional integration suite additionally checks Group add/edit GET and POST requests with Service membership and finding object links in both list/detail pages. Existing coverage includes the old-dashboard redirect, group hierarchy rendering, service endpoint inference, alert configuration, and denial of unprivileged settings access. Django's test runner requires permission to create a test database; do not point an ad hoc test setup at production data.

Also verify on the test VM:

1. Existing encrypted material remains decryptable using the unchanged Fernet key.
2. Single and bulk bundle downloads contain only the selected material, and PFX files open with the chosen password mode.
3. Existing alert rules are visible under additional rules; save the new settings, then explicitly test email/webhook delivery.
4. NetBox's RQ worker processes the periodic health/alert job.
5. Verify constrained non-admin users only see permitted certificate/group/finding data.

See UPGRADE.md for install, backup, verification, and rollback commands.
