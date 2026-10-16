# Groups and Services restore

Use **Backup services / Restore services** on Services, and **Backup groups / Restore groups** on Groups. Material exports and Import Objects handle certificates, keys, CSRs, and bundles. The standalone full-backup page and full-snapshot API endpoints have been removed.

Restore accepts the current ZIP or JSON exports, merges objects with matching names, and resolves relationships using names/fingerprints. Missing or ambiguous relationships are skipped with warnings. Import cryptographic material first when moving to another NetBox. Restoring does not erase unrelated objects. Metadata restore requires a superuser and validates object values and typed group memberships.

`POST /api/plugins/ssl-certificates/import-metadata/` accepts multipart `upload` and optional `kind` (`service` or `artifactgroup`). The response contains `imported` and `warnings`. Use a superuser token with write access. A mixed Groups/Services inventory archive is accepted when `kind` is omitted.

For disaster recovery, back up the NetBox database and preserve the plugin encryption key and normal NetBox configuration. Inventory exports are not a complete database backup and do not include private-key access history or alert credentials.
