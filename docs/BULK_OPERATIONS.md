# Bulk Import and Material Export

## Bulk import

The unified **Import Objects** workflow accepts multiple uploaded files in one request.

Version 0.5.0 adds two batch-Bundle paths while preserving the existing object importer:

1. **Multiple archives:** each uploaded ZIP/TAR/RAR archive is treated as an independent logical input. Uploading five Bundle archives imports five Bundles in one transaction.
2. **Multiple loose Bundle sets:** loose certificate/private-key/CSR files are grouped by `public_key_fingerprint`. Each identity with at least two distinct primary roles becomes its own Bundle candidate.

Standalone certificates, private keys, and CSRs continue to import normally. A batch of ten unrelated certificates therefore remains ten certificate imports rather than being forced into Bundles.

The whole multi-archive/multi-Bundle operation is atomic: an error in one Bundle aborts the batch rather than leaving a partially completed batch.

### Ambiguous identities

A public-key identity containing more than one candidate for the same primary Bundle role is rejected. Package ambiguous alternatives into separate archives so the intended Bundle membership is explicit.

CA certificates can be discovered as chain members for loose Bundle groups using issuer/subject relationships. The existing root-CA identity and certificate-chain reconciliation mechanisms remain unchanged.

## Bulk material export

The Certificates, Private Keys, CSRs, and Bundles list pages each expose **Export Material**.

The exporter operates on all objects the current user is authorized to export that match the current page filters:

| Page | Permission action | ZIP content |
| --- | --- | --- |
| Certificates | `download` | PEM certificates (`.crt`) |
| Private Keys | `download` | Decrypted private keys (`.key`) |
| CSRs | `download` | PKCS#10 requests (`.csr`) |
| Bundles | `export` | One directory per Bundle containing certificate, private key, CSR, and chain certificates when present |

NetBox ObjectPermission scope is applied before exporting. The material exporter does not turn NetBox's normal metadata/table export into a secret-material export; it is a separate protected endpoint.

Bulk ZIP responses use cache-prevention headers. ZIP members are written with restrictive `0600` file-mode metadata. Large archives use a spooled temporary file rather than requiring the complete archive to remain in Python process memory.

> **Security:** Private-key exports contain plaintext private-key material inside the downloaded ZIP. Store, transfer, and delete these exports as sensitive secrets.

## Certificate Authority UI retirement

The `CertificateAuthority` model, root-identity synchronization, certificate `authority` relationship, chain validation, and read-only REST API remain in place.

The dedicated **Certificate Authorities** web navigation/page is retired. Legacy `/certificate-authorities/...` web URLs redirect to the Certificates inventory with an appropriate CA filter so bookmarks and `get_absolute_url()` calls do not break.
