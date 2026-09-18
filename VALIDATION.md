# Validation for 1.3.5

The Service, Object Link, and Alert Channel form overrides incorrectly assumed parent clean() returns a dictionary. NetBox's CheckLastUpdatedMixin validates in place and returns None. They now call the parent and use self.cleaned_data, preserving NetBox validation.

The mandatory NetBox 4.5.9/4.5.10 CI/release matrix runs the plugin integration suite on disposable PostgreSQL/Redis databases. It covers Service create/edit, endpoint defaults, custom deployment, invalid ports/metadata, stale edits, Object Link visibility, Alert Channel create/edit and validation, and existing inventory/UI workflows. No tests run against the user's VM or send real notifications.

Standalone checks, compilation, distribution checks, real model/migration comparison, and 0024-to-0025 data preservation remain required. No new model/migration change is intended in 1.3.5. Run migrate on upgrades to apply any previously outstanding migrations.

## Historical validation for 1.3.4

## Migration-state repair

- Started from published v1.3.3 (`60cbbd8`) and reproduced a pending AlterField for AlertRule.statuses using the actual NetBox 4.5.9 app registry, migration graph, and Django autodetector.
- The historical default was `0014_certificate_management_v1.default_alert_statuses`; the runtime field uses `models_v1.default_alert_statuses`. Both return ["active"], but their distinct callable identities produce migration drift.
- Added 0025_alertrule_statuses_default. All earlier published migrations remain unchanged. The same detector now reports no pending plugin changes against both 4.5.9 and 4.5.10 source trees. The local verification environment uses NetBox 4.5.9's pinned dependencies; CI installs each version's own requirements.
- Added mandatory CI/release checks with real NetBox, PostgreSQL 16, and Redis 7 on both supported versions. They apply the full migration graph, run Django checks and `makemigrations --check --dry-run`, and upgrade from 0024 to 0025 with seeded alert rules to verify that all stored values are preserved.
- Existing 133 standalone tests, compilation, metadata checks, and distribution checks remain part of release validation. The local state check requires no database connection and does not inspect the user's VM.

The earlier 1.3.3 report covered standalone/component checks but did not perform a real NetBox model/migration comparison. Its claim of no outstanding migration requirements was incorrect. The new check closes that gap. Database-backed checks run in the GitHub workflow, not against production data.

## Reproduce the migration-state check

With a checkout of a supported NetBox release and its Python dependencies installed:

```bash
python scripts/check_migration_state.py --netbox-root /path/to/netbox
```

The script uses the disposable configuration in tests/netbox_configuration.py and compares migration files to real runtime models without connecting to a database. It fails if a plugin migration is missing. For actual database application and data preservation, use the NetBox migrations workflow.

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
