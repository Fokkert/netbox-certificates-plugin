# REST API

This document describes the REST API for NetBox Certificates Plugin **0.4.11**.

## Base URL

```text
/api/plugins/ssl-certificates/
```

Examples in this document use:

```bash
export NETBOX_URL="https://netbox.example.com"
export NETBOX_TOKEN='nbt_KEY.SECRET'
```

NetBox 4.5 v2 tokens use Bearer authentication:

```bash
curl -sS \
  -H "Authorization: Bearer ${NETBOX_TOKEN}" \
  "${NETBOX_URL}/api/plugins/ssl-certificates/certificates/"
```

Use a properly trusted TLS certificate/CA. Do not normalize `curl -k`/`--insecure` into production automation.

## Authentication and sensitive-token policy

Most API endpoints require an authenticated NetBox user and the corresponding NetBox ObjectPermission.

Several cryptographic operations additionally require a **write-enabled NetBox API token**. A browser session or read-only API token is intentionally insufficient for these sensitive endpoints.

Private-key material has a stronger overlay: creating/replacing/downloading private-key material and exporting private-key-bearing/PFX bundles requires a **NetBox superuser** using a **write-enabled API token**.

## Common response codes

| Code | Meaning |
| --- | --- |
| `200` | Successful read/update/action. |
| `201` | Object/import successfully created. |
| `204` | Successful deletion. |
| `400` | Client validation error, invalid cryptographic combination, invalid payload, or size/format problem. |
| `403` | Authentication/permission/token/superuser policy denied the request. |
| `404` | Object does not exist or is hidden by constrained object permissions. |
| `405` | HTTP method is deliberately unavailable for the endpoint. |

NetBox object constraints may deliberately conceal an object as `404` rather than returning `403`.

## Resource endpoints

### Certificates

```text
GET/POST   /certificates/
GET/PATCH/PUT/DELETE /certificates/{id}/
GET        /certificates/{id}/download/
GET        /certificates/expiration-summary/
GET        /certificates/inventory/
```

Standard CRUD is controlled by `view/add/change/delete_certificate` ObjectPermissions.

#### Direct create

```bash
jq -n \
  --arg name "example.com" \
  --arg material "$(cat example.crt)" \
  '{name:$name, source_filename:"example.crt", material:$material}' \
| curl -sS -X POST \
    -H "Authorization: Bearer ${NETBOX_TOKEN}" \
    -H "Content-Type: application/json" \
    --data-binary @- \
    "${NETBOX_URL}/api/plugins/ssl-certificates/certificates/"
```

The serializer parses/normalizes the material and derives cryptographic metadata.

#### Download

```bash
curl -sS \
  -H "Authorization: Bearer ${NETBOX_TOKEN}" \
  -o certificate.crt \
  "${NETBOX_URL}/api/plugins/ssl-certificates/certificates/123/download/"
```

Requirements:

- authenticated user;
- write-enabled API token;
- `download` custom ObjectPermission for Certificate;
- target object visible through `view` scope/constraints.

### Certificate Authorities

```text
GET /certificate-authorities/
GET /certificate-authorities/{id}/
```

The API is intentionally read-only (`GET`, `HEAD`, `OPTIONS`). Root CA identities are derived from stored root certificates.

### Private Keys

```text
GET/POST   /private-keys/
GET/PATCH/PUT/DELETE /private-keys/{id}/
GET        /private-keys/{id}/download/
```

Normal serializers expose metadata only. They do **not** expose decrypted private-key material.

Material creation/replacement/download requires:

- a write-enabled token;
- NetBox superuser status;
- the applicable add/change/download ObjectPermission.

A non-superuser may still be granted metadata `view/change/delete` permissions without receiving material access.

### CSRs

```text
GET/POST   /csrs/
GET/PATCH/PUT/DELETE /csrs/{id}/
GET        /csrs/{id}/download/
POST       /csrs/generate/
```

#### Direct create

```bash
jq -n \
  --arg name "example.com CSR" \
  --arg material "$(cat example.csr)" \
  '{name:$name, source_filename:"example.csr", material:$material}' \
| curl -sS -X POST \
    -H "Authorization: Bearer ${NETBOX_TOKEN}" \
    -H "Content-Type: application/json" \
    --data-binary @- \
    "${NETBOX_URL}/api/plugins/ssl-certificates/csrs/"
```

#### Generate CSR + Private Key

```text
POST /csrs/generate/
```

This operation creates private-key material and therefore requires a superuser using a write-enabled API token. The exact request fields are exposed by the API OPTIONS/schema and the NetBox UI generation form; RSA key size/signature and SAN types such as DNS, IP, Email, and URI are supported by the plugin.

### Bundles

```text
GET        /bundles/
GET/PATCH/PUT/DELETE /bundles/{id}/
POST       /bundles/{id}/export/
```

Direct `POST /bundles/` returns `405`. Create Bundles through `/import-objects/`.

#### Export parameters

`POST /bundles/{id}/export/` accepts:

| Field | Meaning |
| --- | --- |
| `fmt` | Archive format, normally `zip` or `tar`. |
| `pfx` | Boolean; export certificate/private key as PKCS#12/PFX. |
| `password` | Required for PFX export. |
| `include_chain` | Include certificate chain where available. |

Public-only Bundle export requires the `export` custom action plus view scope and a write-enabled token.

If the Bundle contains a Private Key, export requires a superuser. `pfx=true` is always superuser-only.

Example public bundle export:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer ${NETBOX_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"fmt":"zip","include_chain":true}' \
  -o bundle.zip \
  "${NETBOX_URL}/api/plugins/ssl-certificates/bundles/123/export/"
```

Example PFX export:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer ${NETBOX_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"fmt":"zip","pfx":true,"password":"use-a-secret-manager"}' \
  -o bundle-pfx.zip \
  "${NETBOX_URL}/api/plugins/ssl-certificates/bundles/123/export/"
```

Avoid placing PFX passwords directly in shell history in real automation; inject them from a secret manager or protected environment/file descriptor.

### Artifact Groups

```text
GET/POST   /groups/
GET/PATCH/PUT/DELETE /groups/{id}/
```

Groups are hierarchical inventory groups. Parent/child loops are rejected.

### Artifact Links

```text
GET/POST   /artifact-links/
GET/PATCH/PUT/DELETE /artifact-links/{id}/
```

A user must have visibility to both source and target endpoints. Automatic links are immutable through the API; manual links may be edited/deleted with the relevant permissions.

### Expiration Alert Configuration

```text
GET/POST   /expiration-alert-configurations/
GET/PATCH/PUT /expiration-alert-configurations/{id}/
POST       /expiration-alert-configurations/run-scan/
POST       /expiration-alert-configurations/{id}/test_email/
POST       /expiration-alert-configurations/{id}/test_webhook/
```

This is a singleton. DELETE is intentionally unavailable.

`run-scan` requires a write-enabled token and either superuser status or `change_expiryalertconfiguration`.

`test_email` and `test_webhook` require a write-enabled token plus either the custom `test` permission or change permission. **These actions produce external side effects** and can send real SMTP/webhook traffic.

### Expiration Alert Events

```text
GET    /expiration-alert-events/
GET    /expiration-alert-events/{id}/
DELETE /expiration-alert-events/{id}/
```

Events are worker-generated records. POST/PUT/PATCH are intentionally unavailable.

## Unified Import

```text
POST /import-objects/
Content-Type: multipart/form-data
```

At least one multipart field named `files` is required. Send multiple files by repeating the field.

Example:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer ${NETBOX_TOKEN}" \
  -F 'files=@certificate.crt' \
  -F 'files=@request.csr' \
  -F 'groups=12' \
  -F 'description=Imported by certificate automation' \
  "${NETBOX_URL}/api/plugins/ssl-certificates/import-objects/"
```

Supported form fields include:

| Field | Purpose |
| --- | --- |
| `files` | One or more uploaded certificate/key/CSR/container/archive files. Required. |
| `password` | Password for encrypted key/PFX material where applicable. |
| `archive_password` | Archive password where supported. |
| `import_chain` | Boolean; import certificate chain members. |
| `preserve_archive` | Boolean; preserve the source archive where supported. |
| `owner` | NetBox Owner primary key. |
| `groups` | One or more visible Artifact Group IDs. |
| `description` | NetBox description metadata. |
| `comments` | NetBox comments metadata. |

Permission behavior:

- Certificate import requires `add_certificate`.
- CSR import requires `add_csr`.
- Private-key import additionally requires `add_privatekey`, **superuser status**, and a write-enabled token.
- Bundle creation from matching primary artifacts requires `add_bundle` plus add permission for the member objects created by that transaction.
- Supplied Group IDs must be visible to the caller.

Invalid cryptographic combinations (for example, certificate/key A with CSR B) return HTTP `400` and are rolled back atomically.

## Filters, pagination, and OPTIONS

The plugin uses NetBox's REST framework conventions. List endpoints support NetBox pagination and the filter fields exposed by each plugin filterset. Use `OPTIONS` on an endpoint to inspect writable fields and choices for the installed version.

Examples:

```bash
curl -sS \
  -H "Authorization: Bearer ${NETBOX_TOKEN}" \
  "${NETBOX_URL}/api/plugins/ssl-certificates/certificates/?status=valid&limit=50"

curl -sS -X OPTIONS \
  -H "Authorization: Bearer ${NETBOX_TOKEN}" \
  "${NETBOX_URL}/api/plugins/ssl-certificates/certificates/"
```

## Custom permission actions

The ObjectPermission `actions` values used by this plugin are:

| Model | Action string | Django permission checked |
| --- | --- | --- |
| Certificate | `download` | `netbox_certificates.download_certificate` |
| PrivateKey | `download` | `netbox_certificates.download_privatekey` |
| CSR | `download` | `netbox_certificates.download_csr` |
| Bundle | `export` | `netbox_certificates.export_bundle` |
| Bundle | `export_pfx` | `netbox_certificates.export_pfx_bundle` |
| ExpiryAlertConfiguration | `test` | `netbox_certificates.test_expiryalertconfiguration` |

For custom actions, the plugin also applies the object's view restriction, so a custom action does not grant visibility to otherwise-hidden objects.

## Secret handling recommendations

- Prefer NetBox v2 API tokens.
- Use write-enabled tokens only for principals that need sensitive/write operations.
- Do not log bearer tokens, private-key PEM, PFX passwords, SMTP passwords, or webhook secrets.
- Store API tokens/PFX passwords in a secret manager.
- Use valid TLS and a trusted internal/public CA instead of disabling verification.
- Rotate credentials after accidental exposure.
- Back up the plugin Fernet encryption key independently of the database.
