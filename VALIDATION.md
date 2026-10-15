# Validation for 1.5.0

The release gate runs standalone checks, real NetBox 4.5.9/4.5.10 model/migration comparisons, PostgreSQL migration application and upgrade-data preservation, and the plugin integration suite.

New integration cases cover SAN-only/wildcard/IP naming, PFX naming, key-first imports, custom-name preservation, typed import assignment, group membership constraints in both directions, REST validation, type-aware UI submissions, configurable table relationships and permissions, repeat-day validation, and seven-day reminder suppression across daily scans. Notification delivery is mocked in tests; no real email or webhook is sent.

The disposable upgrade check seeds old mixed and single-type groups and generated/custom names at migration 0025, applies 0026/0027, and verifies memberships, hierarchy classification, key ciphertext, all certificate fields other than intended names, and custom names.

The migrations are required. All previous migration files remain unchanged. No test accesses the user's VM. Passing checks covers these scenarios, not every possible deployment or browser interaction.

Run local checks with `python scripts/release.py`; publish with `python scripts/release.py --publish` after a clean reviewed commit and successful CI. Run real NetBox tests with `python manage.py test netbox_certificates.tests` on a disposable database. The production upgrade requires migrate, never generating local migrations.

Backup coverage includes encrypted and unencrypted archives, re-encryption with a different destination key, remapped relationships, invalid-file/password/confirmation rejection, transaction rollback, missing metadata members, and UI/API access checks. No actual user VM is modified by these checks.
