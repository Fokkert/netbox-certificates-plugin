# Changelog

## 1.0.0

- Add Services with many-to-many cryptographic relationships and native NetBox object links.
- Add Certificate Policies and structured Health and Validity findings.
- Add configurable alert rules, SMTP/webhook channels, and delivery history.
- Restore Certificate Authorities as a view and API of CA Certificate objects.
- Replace Inventory with Cryptographic Vault and add an expandable Group tree.
- Add relationship-aware filtering, global search, GraphQL coverage, and NetBox-native metadata support.
- Fix filtered material export and add SHA-256 manifests to multi-file exports.
- Replace legacy relationship, CA identity, and expiration-alert public interfaces with the 1.0 object model.

## 0.5.0

- Add batch import of multiple Bundle archives in one transaction.
- Add loose multi-Bundle import by grouping certificate/private-key/CSR candidates by public-key fingerprint while leaving unrelated standalone objects independent.
- Add protected **Export Material** actions to Certificates, Private Keys, CSRs, and Bundles, including filter-aware bulk ZIP export.
- Retire the dedicated Certificate Authorities web navigation/page. Root-CA identity synchronization, certificate authority relationships, chain resolution, and the read-only REST API remain intact; legacy web URLs redirect to Certificates.
- Keep the NetBox 4.5.9-4.5.10 compatibility gate and Python 3.12+ requirement.
- No database schema migration is required.

## 0.4.11

- Prepare the release for standard Python packaging (wheel/sdist), GitHub Releases, PyPI Trusted Publishing, Apache-2.0/NOTICE attribution, and public API/installation documentation.
- Fix direct REST creation of Certificates and CSRs on NetBox 4.5.x. Their serializers now parse and normalize cryptographic material before NetBox `ValidatedModelSerializer` performs model `full_clean()`, preventing valid PEM input from being misreported as blank.
- No database migration or new static asset.

## 0.4.10

- Unified import now returns HTTP 400 Bad Request for expected client-side validation failures instead of HTTP 500.
- Mismatched Certificate/Private Key/CSR public-key identities remain atomically rejected with no objects persisted.
- Missing uploads and oversized unified-import requests now use the same HTTP 400 validation semantics.

## 0.4.9

- Fix the CSR SAN Type enhanced dropdown regression introduced in 0.4.7.
- Clone the live RSA Signature TomSelect settings so SAN Type uses the same NetBox static-choice behavior instead of an editable-looking control.
- Explicitly seed DNS, IP, Email, and URI into every SAN Type TomSelect instance.
- Render the SAN dropdown under `body` and remove the table overflow wrapper so the option menu cannot be clipped.
- No database migration or static-asset collection is required.

## 0.4.7

- Render dynamically-created CSR SAN Type selectors with the same NetBox TomSelect control used by native ChoiceField dropdowns such as RSA Signature.
- Preserve dynamic Add SAN/remove-row behavior while synchronizing values through the underlying select element.

## 0.4.6

- Render CSR SAN entries as a NetBox-style table/list with native table, form-control, form-select, and action-button styling.
- Rebuild the Expiration Alerts configuration layout so each field uses one consistent full-width NetBox horizontal form grid, eliminating nested unequal Bootstrap columns that misaligned labels and controls.
- No database migration and no new static asset are required.

## 0.4.5

- Removed retired compatibility UI/API aliases instead of preserving them during development.
- Renamed the current Expiration Alerts UI route to `expiration-alerts/` and REST endpoints to `expiration-alert-*` only.
- Removed the duplicate Certificate Authority list route name, legacy Bundle import redirects, Bundle `import-archive` API action, and single-file import parameter alias.
- Expanded object-list/API filters to cover all meaningful model fields, relations, metadata, and timestamps.
- Preserved partial Bundle imports: any two matching primary objects are accepted and labeled Partial; all three are required only for Complete.

## 0.4.4

- Made Group parent choices hierarchy-aware: an existing Group can only choose a parent at its current level or above, while itself, descendants, and deeper Groups are excluded.
- Removed explicitly duplicated Owner placement from PrimaryModel edit fieldsets and retained NetBox's native Owner handling.
- Added native NetBox bulk export to Groups and Certificate Authorities.
- Expanded list filters with page-specific fields for Certificates, Private Keys, CSRs, Bundles, Groups, and Certificate Authorities.
- Renamed the user-facing **Expiry Alerts** surface to **Expiration Alerts** while keeping existing URL/API identifiers for compatibility.
- Reorganized the Expiration Alerts configuration into consistent Alert Policy, SMTP Connection, SMTP Security, Delivery, Webhook Connection, and Webhook Options sections.
- Removed non-essential import/export/link guide banners and the main-dashboard widget's **Open dashboard** link.
- Certificate Authorities are now root-only identities. Intermediate issuer identities are removed, and certificates are associated with the stored self-signed root CA identity when a complete root path is available.
- Restored strict Bundle status semantics: **Complete** requires Certificate + Private Key + CSR; any missing primary object makes the Bundle **Partial**.
- Added migration `0013_root_authorities_and_bundle_status` to normalize existing CA identities and Bundle statuses and update expiration-alert display metadata.
- Kept the 0.4.3 Inventory colors and bumped the stylesheet cache key to 0.4.4.

## 0.4.1

- Fixed the `ArtifactGroup` REST router basename so NetBox 4.5.9 dynamic Group fields resolve the expected `artifactgroup-list`/`artifactgroup-detail` endpoints instead of raising `NoReverseMatch`.
- Aligned Group UI route names with the `ArtifactGroup` model (`artifactgroup_list`, `artifactgroup`, and `artifactgroup_delete`) for NetBox generic view compatibility.
- Restored the 0.3.12 plugin navigation structure. `Expiry Alerts` remains under Operations; `Import Objects` is under Operations; `Certificate Authorities` is added under Overview; `Groups` is added under Inventory.
- Removed navigation-level Import buttons and the duplicate custom `Add Group` button. Page-level Import/Generate controls remain where they are useful.
- No database migration and no static-file change.

## 0.4.0

- Fixed NetBox bulk editing by adding proper `PrimaryModelBulkEditForm` forms and bulk-edit routes for Certificates, Private Keys, CSRs, Bundles, and Groups.
- Certificate bulk edit can change Alert Trigger, Trigger Unit, Owner, Groups, Description, Comments, and Tags. Other artifact bulk forms expose their normal non-unique administrative fields.
- Added configurable expiry-alert repeat behavior: `Send once per trigger` (legacy behavior) or `Send every check while due`.
- Added first-class Groups. Certificates, Private Keys, CSRs, and Bundles have a native many-to-many `groups` field, table column, filters, UI management, and REST API support.
- Added unified `Import Objects` UI/API ingestion. Content is inspected cryptographically and imported as Certificate, Private Key, CSR, chain/container, or Bundle according to what is actually present.
- Added a Certificate Authorities overview. Any imported X.509 certificate with CA BasicConstraints appears automatically.
- Expanded reciprocal navigation among Bundles, chain CAs, Certificates, Private Keys, CSRs, Groups, and generic NetBox links.
- A valid Bundle is complete when it contains at least two matching primary artifacts, consistent with Bundle validation rules.
- Added compatibility redirects from the legacy Bundle import URLs to Import Objects.
- Added migration `0010_groups_and_repeat_alerts`.

## 0.3.12

- Fixed expiry-alert scan cadence drift by running the NetBox system-job heartbeat every minute while retaining the configured due-time gate.
