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
