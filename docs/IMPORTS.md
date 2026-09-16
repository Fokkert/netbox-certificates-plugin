# Imports

## Mixed cryptographic inventory

Use **Import Objects** or multipart `POST /api/plugins/ssl-certificates/import-objects/`. Upload several files using the repeated `files` field. Certificates (including CAs), private keys, CSRs, bundles, and chains can be mixed in one request. Content is detected independently of file extensions.

Supported content: PEM, DER, PKCS#7/CMS, PKCS#12/PFX, ZIP, TAR and compressed TAR. RAR requires the optional dependency and its extraction backend. A PEM file can contain multiple object types. Nested archives can contain several independent bundles. `password` decrypts PEM/PFX material; `archive_password` unlocks archive members. Split inputs into separate requests when they need different passwords.

The complete batch is parsed and checked before writes. Invalid members, tampered CSR signatures, invalid model data, and unauthorized changes reject the batch without partial imports. CA-only import additionally requires every parsed object to be a certificate with Basic Constraints `CA=true`.

## Identity and relationships

Certificates and CSRs are deduplicated by fingerprint; private keys by public-key fingerprint. Existing visible objects are reused without replacing their names or metadata. Requested Group additions to an existing object require change permission. Matching objects hidden by permissions cause rejection rather than exposing them.

After all objects are saved, the importer links matching certificates/keys/CSRs by public-key fingerprint, resolves issuer chains, and reconciles bundles. Bundle selection favors an end-entity certificate over a CA and then the latest expiry; all distinct certificates remain in inventory. Changing an existing bundle requires its change permission; creating a bundle requires add permission. Groups selected on the import apply to imported/reused objects and their reconciled bundles.

`import_chain=true` includes CA certificates embedded alongside leaf material. The UI enables this by default. Turn it off to omit those accompanying certificates; a standalone CA file is still imported. The CA-only action always validates the full input.

Original archives are encrypted and retained only when the source archive represents a single primary public-key identity and `preserve_archive=true`. A mixed inventory archive is not copied into every bundle.

## Limits

- Combined uploaded bytes: 64 MiB.
- Counted expanded content, including nested containers: 128 MiB.
- File/parsed-object limit: 10,000; archive containers also count toward the file limit.
- Maximum archive nesting: three levels.

Proxy and NetBox request limits may impose a lower upload limit. Split larger batches. Archive members are read without extracting files onto server paths; absolute paths and parent traversal are rejected.

Known manifest, README, operating-system metadata, and inventory `metadata/*.json` files inside archives are skipped and reported. Unknown invalid files reject the request. Metadata-only archives contain no importable cryptographic objects and are rejected with a validation message. Inventory metadata snapshots do not recreate Services, Groups, alert configuration, history, or links to external NetBox objects; use the relevant NetBox/API editing/import interfaces for user-managed metadata and a database backup for full restoration.

## API results

A successful request returns created objects, reused identities, reconciled bundle IDs, and ignored filenames. Select owner/groups by ID; those choices are permission-scoped. Booleans must be valid Boolean values, and invalid owner/group IDs are rejected. API import requires a write-enabled token and add permission for each submitted cryptographic type.

## Defaults and immutable material (1.3.0)

Preferences controls the initial chain-import and source-archive-preservation options in both UI and API. Explicit request options override these defaults. Existing cryptographic objects retain their material: import renewal/replacement material as new objects, allowing fingerprint matching, issuer verification, and automatic Supersedes reconciliation to maintain relationships. Friendly names and organizational metadata remain editable.

The Vault CA card opens the filtered Certificates list. Its **Import CA Certificates** action retains strict CA-only validation. CA import/export API routes remain available.
