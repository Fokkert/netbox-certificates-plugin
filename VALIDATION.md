# Validation for 1.9.1

The published v1.9.1 release passed the GitHub Actions release gate: standalone checks and package builds, plus real NetBox 4.5.9 and 4.5.10 integration checks with PostgreSQL and Redis. Publication depends on successful checks.

## Release checks

- Python compilation, release metadata consistency, standalone behavioral tests, whitespace checks, wheel/source builds, and distribution metadata validation.
- Real NetBox model/migration comparison, migration application, Django system checks, and checks for missing or unapplied migrations.
- Upgrade checks for alert defaults, typed Groups and generated names, and removal of Service deployment metadata. The 0031-to-0032 check verifies that other Service values and certificate memberships survive removal of the JSON field.
- NetBox form, view, API, permission, import/export, health, and alert integration tests.

## Regression coverage

Coverage includes content-detected imports; SAN-only, wildcard, and IP naming; PFX naming; key-first imports; custom-name preservation; typed membership validation; derived-field protection; individual/bulk deletion; configurable columns; empty exports; cleared filters; and alert repeat intervals.

Dashboard tests cover permissions, sections, pagination, expiration limits, activity history, and private-key access visibility. Import Objects and Export Inventory views are checked for references to the removed backup route. Native form heading markup and CSR form rendering are covered, as are removal of Service deployment metadata and tolerance of old metadata archives/table preferences.

Service-check tests use fake sockets for direct TLS, SNI, PostgreSQL/MySQL negotiation, and invalid or truncated responses. Integration tests cover both opt-in switches, disabled Services, matching/mismatching certificates, and connection failures. Notification delivery is mocked; tests send no real email/webhooks and contact no live Service endpoints.

Groups/Services restore coverage includes metadata merging, missing relationships, validation, and authorization. Full-snapshot backup/restore is no longer a supported interface.

## Running checks

Run `python scripts/release.py` for local checks and package validation. Run `python manage.py test netbox_certificates.tests` with real NetBox on a disposable database. The complete PostgreSQL/Redis environment is defined in `.github/workflows/migrations.yml`.

Production upgrades apply the supplied migrations through `0032_remove_service_deployment_metadata`; do not generate migrations on the VM. See [UPGRADE.md](UPGRADE.md).

No test accesses the user's VM. Passing checks verifies the covered scenarios; it does not guarantee every deployment, browser interaction, or possible input is error-free.
