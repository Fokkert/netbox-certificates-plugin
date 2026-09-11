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

An authorized export with no matching records returns HTTP 200 and a valid archive with `count: 0` in the manifest. Metadata archives also contain `objects.json` with `[]`. This applies to an empty CA inventory and an empty Health and Validity inventory. A genuinely invalid filter returns HTTP 400 with field-specific errors; lack of export permission returns HTTP 403.

## Bundle choices

Single and bulk bundle export forms ask whether to convert the certificate and key into PFX, whether to protect the PFX with a password, and whether to include the certificate chain. Unprotected PFX requires explicit selection; a protected PFX needs a password. Single exports offer ZIP/TAR; bulk material exports use ZIP. PFX replaces the separate certificate/key files and still includes the CSR when present. Chain inclusion is honored in both PFX and separate-file modes.

The REST API exposes equivalent filtered exports; see [API](API.md). Material API access requires a write-enabled API token. Plaintext private-key exports additionally require a superuser, including direct UI downloads and bundles containing keys.

## Bundle filenames (1.1.2)

Single Bundle exports use the certificate's name: `example.com's Bundle.zip` or `example.com's Bundle.tar`. The archive directory is `example.com's Bundle/` and its PFX file is `example.com.pfx`. The API Bundle export uses the same archive/PFX naming. Bulk exports keep the outer `bundles-material.zip` filename and use these named directories inside it. Duplicate directory names receive `(2)`, `(3)`, etc., including case-insensitive collisions.

If a Bundle has no certificate, its Bundle name is used. Unsafe path characters are replaced; blank names fall back to the Bundle ID. Standalone certificate/key/CSR filenames, manifests, permission checks, PFX passwords, and chain options keep their existing behavior.
