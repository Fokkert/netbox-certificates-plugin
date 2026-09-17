# Validation for 1.3.2

## Completed in the development workspace

- Started from published v1.3.1 (`7a14220`).
- 127 standalone Python tests pass, retaining the existing cryptographic/import/export/permission regressions. New tests render the actual Django inventory selector and verify styled checkbox inputs, matching label IDs, initial values, retained bound selections, and empty/unknown selection errors.
- Headless Edge checks use the rendered production inventory partial, Bootstrap 5.3, and the production CSS and selection JavaScript. They cover checkbox/label clicks, keyboard selection, Select all/Clear, submitted form values, selected-state colors, and dark/light layouts at 1920px and 375px.
- Browser checks confirm bounded forms are centered, remain at most 1088px wide, and do not overflow on mobile; Group Search/Clear controls have matching heights and alignment. This is a component fixture, not a running NetBox UI.
- The actual critical, test, and recovery email templates were rendered and inspected at desktop/mobile widths. Existing tests verify escaping and multipart delivery with Django's in-memory backend. These checks do not establish rendering in every email client.
- Release metadata, compilation, whitespace, standalone route/name contracts, wheel/sdist builds, and distribution metadata are checked by the publishing helper. No database migration, API, or permission definition changes in this patch.

No external email or webhook was sent during these checks. Delivery tests use mocks or Django's in-memory mail backend. No live NetBox/PostgreSQL/Redis stack is available here; runtime testing remains on the user's VM after pip installation.

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
