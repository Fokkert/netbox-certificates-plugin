# Exports

## Native metadata export

List pages use NetBox's native export mechanism for table and metadata exports.

## Material export

Material export is available for:

- Certificates
- CA Certificates
- Private Keys
- CSRs
- Bundles

The exporter first restricts the queryset by ObjectPermissions and the applicable sensitive-action checks, then applies the current FilterSet.

List-view presentation parameters such as pagination, ordering, and column state are excluded from FilterSet validation. Saved-filter identifiers are preserved and resolved before export.

## Manifests

Multi-file exports include `manifest.json`.

Material manifests contain:

- plugin version
- export timestamp
- object type
- object count
- active filters
- object IDs
- filenames
- SHA-256 checksums
- available certificate/public-key fingerprints
- sensitivity metadata

Single Bundle ZIP/TAR exports also include a manifest. Direct single-file Certificate, CSR, or Private Key downloads do not add a separate manifest.

## Metadata archives

Metadata-oriented objects export:

```text
manifest.json
objects.json
```

Cryptographic material and encrypted secret fields are excluded.

## Sensitive exports

Authorized Private Key and private-key-containing Bundle exports contain decrypted key material. Downloaded files and archives must be handled as secrets.

Responses use cache-prevention headers and restrictive archive member modes.

## Empty results and validation

An authorized export with no matching records returns HTTP 200 with a warning, without an attachment. UI users see "There are no objects available to export with the current filters and permissions."; API clients receive `{"warning": "There are no objects available to export with the current filters and permissions.", "count": 0}`. This includes empty CA, Health, filtered, and mixed inventory exports. Invalid filters still return HTTP 400 with field-specific errors; missing permission returns HTTP 403.

## Bundle choices

Single and bulk bundle export forms ask whether to convert the certificate and key into PFX, whether to protect the PFX with a password, and whether to include the certificate chain. Unprotected PFX requires explicit selection; a protected PFX needs a password. Single exports offer ZIP/TAR; bulk material exports use ZIP. PFX replaces the separate certificate/key files and still includes the CSR when present. Chain inclusion is honored in both PFX and separate-file modes.

The REST API exposes equivalent filtered exports; see [API](API.md). Material API access requires a write-enabled API token. Plaintext private-key exports additionally require a superuser, including direct UI downloads and bundles containing keys.

## Bundle filenames (1.1.2)

Single Bundle exports use the certificate's name: `example.com's Bundle.zip` or `example.com's Bundle.tar`. The archive directory is `example.com's Bundle/` and its PFX file is `example.com.pfx`. The API Bundle export uses the same archive/PFX naming. Bulk exports keep the outer `bundles-material.zip` filename and use these named directories inside it. Duplicate directory names receive `(2)`, `(3)`, etc., including case-insensitive collisions.

If a Bundle has no certificate, its Bundle name is used. Unsafe path characters are replaced; blank names fall back to the Bundle ID. Standalone certificate/key/CSR filenames, manifests, permission checks, PFX passwords, and chain options keep their existing behavior.

## Mixed inventory ZIP

Use **Export inventory** on the Vault, or API `POST export-inventory/`. Choose any combination of crypto types and metadata types. Material includes the matching bundle chain and separate PEM files; use the individual/bulk Bundle exporter for PFX choices. The mixed exporter iterates records in chunks and spools the ZIP to disk beyond 8 MiB. It includes per-file SHA-256 checksums and object references in a manifest. All types use their existing scoped export permissions; any unauthorized selection rejects the request.

Non-crypto records are JSON snapshots under `metadata/`, without encrypted secrets or private material. Related IDs are visibility-scoped. Reimporting this ZIP restores/reuses crypto objects and reconstructs their crypto relationships, but skips metadata snapshots; it is not a complete database restore. The importer has documented upload/expansion limits, so exceptionally large exports may need to be split into filtered batches before reimport.

## Inventory selection (1.3.2)

Export inventory uses a responsive grid of labeled checkboxes with visible checked states. Click a label or use Tab and Space to toggle a type; Select all object types and Clear selection update the selection count. At least one valid type is required. Certificates, private keys, CSRs, and Bundles remain selected initially; a failed export preserves your submitted choices. Existing object and private-key export permissions still apply.

## Runtime version (1.3.1)

Every newly generated material, Bundle, metadata, and inventory manifest reads `plugin_version` from the plugin's shared runtime version constant. Previously downloaded archives remain unchanged. Re-export after upgrading to obtain a manifest showing the installed release.
