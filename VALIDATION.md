# Validation for 1.3.3

## Completed in the development workspace

- Started from published v1.3.2 (`8a9b984`).
- 133 standalone Python tests pass. New tests execute the production Health filter declarations against real Django forms and a small SQLite model: blank/reset choices, repeated values, combined filters, invalid choices, and label/widget behavior. Workflow tests verify preserved resolution timestamps and reopening.
- Reviewed NetBox 4.5.9 filter/form implementations and replaced the dashboard's modifier widgets with simple optional controls. The shared filterset continues to serve UI, REST, export, and bulk operations.
- Rendered the actual Health, Groups, and CSR templates in component fixtures. Headless Edge checks cover filter clearing, invalid-filter recovery, bulk Group selection, saved tree expansion during search, lowercase IP/URI SAN round trips, add/remove SANs, existing-key selection, algorithm controls, and CA path-length enablement.
- Inspected light/dark desktop/mobile previews and verified no page overflow at 1440px and 375px. Fixtures use Bootstrap and production CSS/JavaScript; they do not emulate the entire NetBox frontend.
- Reviewed canonical serializer discovery, routes, derived-field restrictions, action querysets, superuser/write-token checks, stale-link deletion cleanup, and finding reconciliation. Existing regressions for permissions, cryptography, imports/exports, and deletion remain passing. No installed database was inspected or cleaned.
- Release metadata, compilation, undefined-name checks, whitespace, wheel/sdist builds, and distribution metadata are checked by the publishing helper. No new database migration or permission definition.

No external email or webhook was sent. No live NetBox/PostgreSQL/Redis stack is available here; full runtime and migration verification remains on the user's VM after pip installation. These checks do not establish that every possible defect has been eliminated.

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
