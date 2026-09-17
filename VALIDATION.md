# Validation for 1.3.1

## Completed in the development workspace

- Started from published v1.3.0 (`8236130`).
- 124 standalone Python tests pass, including all previous cryptographic/import/export/permission regressions.
- New checks cover shared runtime versions in every manifest and alert payload, HTML escaping and multipart email delivery with Django's in-memory backend, test/recovery/expiration templates, every supported webhook method, TLS/header preservation, redirect/invalid-method rejection, native Group selection and clearing, and filter preservation for Health bulk actions.
- Headless Edge checks exercise the production bulk-selection JavaScript: collapsed child groups, disabled rows, all-query selection, deselection, clearing, and pages without edit controls. Settings width is bounded to 1088px at a 1920px viewport and shrinks to a 375px viewport.
- The actual notification template was rendered, inspected, and checked for overflow at desktop/mobile widths. This does not establish rendering in every email client.
- Release metadata, Python compilation, undefined-name/route checks, whitespace, wheel/sdist builds, and distribution metadata checks passed. Packages include migration 0024, native membership template, selection assets, notification template, and runtime version module.

No external email or webhook was sent during these checks. Delivery tests use mocks or Django's in-memory mail backend. No live NetBox/PostgreSQL/Redis stack is available here; migration/runtime testing remains on the user's VM after pip installation.

## Release checks

```bash
python -m pip install -r tests/requirements.txt
python -m pip install 'setuptools>=77' wheel build twine
python scripts/release.py
```

The helper checks release metadata, compilation, standalone tests, whitespace, wheel/sdist builds, and distribution metadata. It pushes only with `--publish` after a clean commit.

## NetBox runtime verification

This workspace has no running NetBox/PostgreSQL/Redis stack, and no live VM test was performed. As requested, deployment testing happens after pip installation on the user's VM.

The optional integration suite now additionally checks actual NetBox serializer lookup/event serialization, individual and bulk certificate deletion with links, read-only fields, Preferences permissions, and CA redirects. These integration tests were added but not run here. The suite also includes mixed-import database deduplication/relationships, transaction rollback, CSR generation with an existing key, empty exports, retired policy redirects, Group creation/editing, finding links, Services, and restricted alert settings. Run it only on a disposable test database:

```bash
python manage.py check
python manage.py migrate --check
python manage.py makemigrations --check --dry-run netbox_certificates
python manage.py test netbox_certificates.tests
```

After deployment, review migrated global checks and alert scopes, confirm stored secrets remain decryptable, test SMTP/webhook samples, inspect Group hierarchy and constrained-user permissions, import/export a representative mixed batch, and confirm the worker runs scheduled jobs. See [Upgrade](UPGRADE.md) for pip installation and rollback instructions.
