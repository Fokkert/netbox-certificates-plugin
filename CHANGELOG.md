# Changelog

## 1.3.5

- Fix Service, Object Link, and Alert Channel forms using NetBox's in-place cleaned_data after parent validation, avoiding NoneType.get failures on add/edit.
- Retain NetBox custom-field handling, stale-edit protection, object visibility checks, and input validation.
- Run plugin database-backed form/view tests on NetBox 4.5.9 and 4.5.10 before publishing, alongside migration checks.
- Restore the prominent README AI disclosure and align NOTICE/AI_ASSISTANCE with the license disclaimer.
- No new model changes; migration 0025 from 1.3.4 remains packaged.

## 1.3.4

- Add migration 0025_alertrule_statuses_default to align AlertRule.statuses with the runtime default callable. Migration 0014 referenced a different function with the same return value, leaving a persistent pending-model-change warning.
- Preserve existing rule statuses and the default of ["active"] for new rules. Existing published migrations remain unchanged.
- Add a real NetBox migration-state checker and PostgreSQL/Redis CI matrix for 4.5.9 and 4.5.10, including stored-data preservation during 0024 -> 0025 upgrades. Gate PyPI publication on these checks.
- Correct the release/upgrade documentation: 1.3.3 shipped with outstanding migration-state drift; running migrate alone could not resolve it until this repair was packaged.

## 1.3.3

- Fix optional Health severity/status filters: cleared values are accepted, multiple values are combined with OR, and unknown values remain invalid across UI, API, exports, and bulk actions.
- Replace the Health query label Q with Search, remove lookup-modifier widgets from the dashboard, show filter errors, and provide a direct Clear filters link.
- Simplify Groups to plain tree rows and text buttons; preserve saved expansion preferences during search.
- Use consistent CSR form sections, lighter SAN rows, and readable Remove buttons. Preserve case-insensitive SAN prefixes and invalid input during redisplay.
- Preserve the resolution timestamp when editing metadata on resolved findings.
- Review routes, serializers, permission restrictions, stale-link cleanup, and scan reconciliation; retain the existing regression coverage. No new migration or permission definition.

## 1.3.2

- Add a navy email header, status colors, tinted summary panels, and alternating detail rows across all notifications; retain escaping and plain-text alternatives.
- Center bounded Preferences, Alerts Configuration, Group edit, CSR generation, and export forms.
- Render inventory export types as aligned, labeled checkboxes with visible checked/focus states, responsive columns, and accessible validation errors.
- Align search/filter and action buttons, including Groups Search/Clear, at desktop and mobile widths.
- Preserve export permissions, API behavior, stored data, and existing selection logic; no new migration.

## 1.3.1

- Add Select all/Clear selection to the Groups tree, Health findings, and inventory export types; preserve Health filters during all-pages bulk actions.
- Bound settings/export form widths and replace large Group membership boxes with native NetBox multiple-choice selectors.
- Centralize the runtime version used by NetBox, export manifests, email templates, webhook payloads, and User-Agent headers.
- Use one minimal HTML email template with plain-text fallback for tests, findings, recoveries, and legacy expiration reports.
- Add validated webhook HTTP methods to settings, channels, REST, filters, and bulk editing. Migration 0024 preserves POST as the default.


## 1.3.0

- Fix canonical serializer discovery for all public models and request-free event serialization during individual/bulk deletion.
- Clean dangling ObjectLinks and reconcile authority/renewal relationships once per certificate deletion transaction.
- Add Preferences under Overview for scan/alert schedules, warning windows, import defaults, and CSR RSA defaults, with a superuser-only API.
- Replace the standalone Certificate Authorities page with a Vault link to filtered Certificates; preserve old bookmarks and CA import/export APIs.
- Repair legacy link mirroring so automatic relationships cannot appear as editable manual links.
- Protect derived cryptographic fields and material from manual replacement; calculate issuer/Supersedes relationships and keep friendly names editable.
- Add structured, responsive CSR SAN rows and separate Group membership controls for all six member types.
- Add migration 0023, regression coverage, and pip-only upgrade documentation.


## 1.2.0

- Replace public Certificate Policies with five global certificate checks in Alerts Configuration; migrate a single enabled policy and retain legacy rows privately.
- Validate SMTP/email/webhook, endpoint/port, JSON, CSR, and import values consistently across forms, models, and API operations.
- Generate CSRs using an existing Private Key with scoped `use` permission, or create a new key.
- Improve Group hierarchy spacing, action buttons, and icons; use a shield/key plugin menu icon.
- Return a warning for empty native/material/metadata/inventory exports, without an empty download.
- Parse and validate mixed cryptographic uploads atomically, support large/nested batches, reuse identities, and reconcile relationships after all material is saved.
- Add a mixed inventory ZIP export and REST endpoint with material, metadata snapshots, checksums, and scoped permissions.
- Retire policy REST/GraphQL/search surfaces, refresh permissions, and document migration and pip-only deployment.
- Expand standalone validation/signing/archive/route regressions and preserve prior release behavior tests.


## 1.1.2

- Fix the missing Service import that prevented Group add/edit forms from opening; retain membership and hierarchy permission checks.
- Use CSRs throughout display labels and documentation, including a model-state migration that preserves existing CSR permissions.
- Name exported Bundle archives and directories after their certificate, with certificate-named PFX files in both UI and API exports. Sanitize filenames and disambiguate duplicate names in bulk exports.
- Show affected/related object links, finding codes, details, and readable evidence in the Health table and detail view; respect object view permissions and escape displayed values.
- Remove the introductory Alerts paragraph while preserving sample test buttons and delivery settings.
- Add targeted regression checks and update release and pip upgrade documentation.

## 1.1.1

- Reject non-CA certificates, missing CA constraints, and mixed material in dedicated UI/API CA imports; enforce the same rules on CA REST create/update.
- Fix unbound empty filters causing empty export failures and invisible Groups; return valid empty material and metadata archives with manifests.
- Normalize displayed acronyms, refresh the Vault with a neutral responsive layout, and use Group/Subgroup terminology throughout the hierarchy.
- Show visible artifacts and Services inside the group tree, add Service membership editing/API support, and expose bulk selection on Groups and Health pages.
- Use each certificate’s alert trigger/unit, default to 1 calendar month, add table columns, and remove rule-level expiration timing from UI/API controls.
- Keep all Service fields visible with certificates and private keys together.
- Make saved SMTP/webhook sample tests available even while disabled; add singleton settings/test REST endpoints and filtered material/metadata export actions.
- Enforce custom-action object constraints, protect membership removals, make generated evidence read-only, remove inappropriate add permissions, and block automatic-link bulk writes.
- Add migration 0020, regression checks, and updated release, API, permission, and Linux upgrade documentation.

## 1.1.0

- Combine Health and Validity with the Expiration Dashboard; retain a redirect from the old dashboard URL.
- Fix missing HealthFinding edit/delete/list routes and restrict table actions to implemented routes, including read-only alert delivery events.
- Correct health scanning to read the actual certificate validity and SAN fields.
- Replace the Groups list/filter nesting with a folder browser, expandable subgroups, search, new subfolders, and rename/move actions. Allow moves to any non-descendant folder.
- Ask for archive format, PFX conversion, optional PFX password protection, and chain inclusion before single/bulk Bundle exports. Preserve manifests and private-key permission checks.
- Add Service deployment/protocol dropdowns, URL-derived hostname/SNI/port defaults, newline URL entry, and an advanced-options section.
- Add a single superuser alert settings page for email, webhooks, conditions, timing, tests, and delivery history; retain existing advanced rules and APIs.
- Add independently configurable SMTP/webhook TLS verification (enabled by default), bounded SMTP timeouts, no webhook redirects, and sanitized delivery errors.
- Fix once-per-occurrence and recovery notification deduplication.
- Add migration 0019 for alert settings and TLS verification options.
- Add a checked release helper, behavioral tests, and optional NetBox integration tests.
- Retain the NetBox 4.5.9–4.5.10 compatibility gate. Full NetBox/PostgreSQL/Redis integration validation remains required on a test deployment.

## 1.0.5

- Fix NetBox 4.5 migration-state rendering by explicitly serializing TaggableManager target models as extras.Tag.
- Correct the historical 0014 migration and the 0018 Service tags state migration, which must load before any later repair migration can run.
- Keep the runtime Service tags definition consistent with the serialized migration state.
- Add regression coverage for every serialized TaggableManager in the plugin migrations.
- No new migration number is added because the defect is inside migrations that must themselves become loadable.

## 1.0.4

- Fix the remaining NetBox 4.5 reverse-accessor collision on Service tags.
- Explicitly namespace the plugin Service TaggableManager reverse relation.
- Add a state-only migration; no tag data or database schema is changed.

## 1.0.3

- Fix reverse-accessor collisions between the plugin Service model and NetBox core ipam.Service for inherited owner and tags relations.
- Namespace Service default reverse relations using the plugin app label.
- Add a state-only migration; no database schema columns or tables are changed.

## 1.0.2

- Fix NetBox 4.5 compatibility for v1 ChoiceSet definitions.
- Add regression coverage requiring keyed ChoiceSet CHOICES values to use lists.
- No additional database migrations.

## 1.0.1

- Publish the corrected 1.0 package release.
- No additional database migrations.

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
