# REST API

Base path:

```text
/api/plugins/ssl-certificates/
```

## Model endpoints

| Endpoint | Object |
| --- | --- |
| `groups/` | Groups |
| `services/` | Services |
| `bundles/` | Bundles |
| `certificates/` | Certificates |
| `private-keys/` | Private Keys |
| `csrs/` | CSRs |
| `certificate-authorities/` | CA Certificates |
| `health-findings/` | Health Findings |
| `object-links/` | Object Links |
| `alert-rules/` | Alert Rules |
| `alert-channels/` | Alert Channels |
| `alert-events/` | Alert Events |

Standard NetBox REST list, retrieve, create, update, and delete behavior applies according to the model and ObjectPermissions.

## Certificate Authorities

`certificate-authorities/` returns Certificate objects whose parsed X.509 Basic Constraints mark them as CAs.

## Health actions

```text
POST health-findings/refresh/
POST health-findings/{id}/acknowledge/
POST health-findings/{id}/ignore/
POST health-findings/{id}/resolve/
```

Health refresh requires `run_healthscan_healthfinding` or superuser access. Finding status actions require the applicable custom permission and ObjectPermission scope.

## Alert actions

```text
POST alert-channels/{id}/test/
POST alert-rules/{id}/test/
```

Testing requires the corresponding custom `test` permission or superuser access.

## Service relationships

Service serializers expose many-to-many relationships to:

```text
groups
certificates
private_keys
csrs
bundles
```

Policy assignments are retired in 1.2.0.

## ObjectLink

ObjectLink fields:

```text
source_type
source_object_id
target_type
target_object_id
relationship
label
enabled
automatic
```

Endpoint types use Django ContentType references and are restricted to public NetBox/plugin models.

Automatic links are read-only. Manual links can be created, changed, and deleted according to ObjectPermissions.

## Alert secrets

Alert Channel accepts write-only SMTP password and webhook configuration fields. Plaintext and encrypted secret values are not returned by ordinary serializers.

## Filtering

The API uses the same FilterSet architecture as the UI. Service and Group relationships are available as filters on relevant inventory objects.

Raw private-key material and encrypted alert secrets are not filterable.

## Upgrading API clients

See [../UPGRADE.md](../UPGRADE.md) for endpoint changes from 0.5.0.

## 1.1.1 endpoints and behavior

Paths below are relative to `/api/plugins/ssl-certificates/`. API identifiers retain their established lowercase spelling; display labels use uppercase acronyms.

| Method | Path | Behavior |
| --- | --- | --- |
| POST | `certificate-authorities/import/` | Multipart `files` upload; rejects any non-CA item before saving |
| GET | `alert-settings/` | Superuser-only singleton settings, with secrets omitted |
| PATCH / PUT | `alert-settings/` | Update supplied settings; omitted values and saved secrets are preserved |
| POST | `alert-settings/test-email/` | Save supplied settings and send a sample email |
| POST | `alert-settings/test-webhook/` | Save supplied settings and send a sample webhook |
| GET | `{resource}/export-archive/` | Filtered metadata ZIP, or a warning when empty |
| GET / POST | `{crypto-resource}/export-material/` | Filtered material ZIP; bundles require POST options |

Metadata resources: `groups`, `services`, `health-findings`, `object-links`, `alert-rules`, `alert-channels`, `alert-events`. Crypto resources: `certificates`, `certificate-authorities`, `private-keys`, `csrs`, `bundles`. Query parameters use the resource's existing filters; display-only parameters are ignored. Metadata requires `archive_export` and view permission. Material requires `download` (or Bundle `export`), a write-enabled token, and a superuser when keys are included. PFX additionally requires Bundle `export_pfx`.

Bundle bulk export JSON:

```json
{"export_pfx": true, "protect_pfx": true, "password": "chosen-password", "include_chain": true}
```

Set `protect_pfx` to `false` explicitly for an unprotected PFX. Passwords go in the POST body. Bulk exports use ZIP; the existing individual Bundle export actions remain available.

CA resource create/update also rejects leaf certificates. The X.509 parser determines `is_ca`; a client-supplied `is_ca` flag cannot override it. The general multipart importer accepts `ca_only=true` with the same validation.

Certificate creation defaults to `{"alert_trigger": 1, "trigger_unit": "month"}`. Update both fields together when enabling/disabling timing; `{"alert_trigger": null, "trigger_unit": ""}` disables expiration alerts. `expiration_days` is no longer an Alert Rule API field and does not govern delivery.

Group serializers now include `services` alongside the other membership lists, and `members` includes visible services. Updating membership checks permissions for removals as well as additions.

Alert settings accept the fields displayed by the settings form, including `recipients` (an array), `smtp_security` (`starttls`, `ssl`, or `none`), and `smtp_verify_tls` / `webhook_verify_tls`. Password, webhook URL, and webhook headers are write-only; configured flags appear on reads. An empty password or webhook URL preserves the saved value; `clear_smtp_password=true` clears the password and `webhook_headers={}` clears saved headers. Test requests can contain partial settings or `{}` to test saved configuration, and work when a delivery method is disabled. Successful tests return a `detail` message and sample payload. A failed delivery returns HTTP 400 with a sanitized message; saved settings remain saved.

All settings mutations/tests and finding state/scan actions require a write-enabled token. Generated findings/events cannot be created through REST. Event outcome/evidence fields are read-only; descriptive metadata remains editable. Automatic ObjectLinks are excluded from individual and bulk writes. Related object selections require view permission.

## Bundle export filenames in 1.1.2

`POST /bundles/{id}/export/` returns a certificate-named archive, such as `example.com's Bundle.zip`, and PFX conversion produces `example.com.pfx` inside it. Filtered bulk Bundle exports use certificate-named directories and disambiguate collisions. Endpoint paths, request parameters, response formats, token requirements, and permission checks are unchanged. See [Exports](EXPORTS.md).

## 1.2.0 settings, CSR generation, and mixed inventory

`certificate-policies/` is retired. Policy fields are absent from Service and Alert Rule serializers; policy GraphQL queries and relationships are removed. Old UI bookmarks redirect to settings.

`alert-settings/` additionally accepts `minimum_rsa_bits` (2048, 3072, 4096, 8192), `max_validity_days` (null or 1–365000), `require_san`, `allow_wildcards`, and `forbid_key_reuse`. The new finding category is `configuration`. Email addresses, SMTP host/port, webhook URL/headers, timing, and these check values are validated even when delivery is disabled. Ports must be 1–65535. Webhook URLs must be HTTP(S) without embedded credentials. Invalid inputs return field errors.

`POST csrs/generate/` accepts the existing CSR options plus `existing_private_key` (Private Key ID). Omit it to create a key. Example:

```json
{"common_name": "example.com", "sans": ["DNS:example.com"], "existing_private_key": 42}
```

The response contains CSR/key metadata, never private material. Signing with an existing key requires its scoped `use` and view permissions, CSR add permission, and permission to create/change the matching Bundle. A new key requires Private Key add permission instead of `use`. Both modes require a write-enabled token. The same form validation applies to UI and API: SAN types/values, email, country, key algorithm settings, and usages are validated. SAN input can be newline-separated text, strings in an array, or `{ "type": "DNS", "value": "example.com" }` objects.

`POST import-objects/` accepts mixed multipart uploads as described in [Imports](IMPORTS.md). It returns `created`, `reused`, `bundle_ids`, and `ignored_files`; `reused_ca_ids` remains for compatibility. Related IDs and input types are validated.

`POST export-inventory/` accepts a non-empty `types` array:

```json
{"types": ["certificate", "privatekey", "csr", "bundle", "artifactgroup", "service"]}
```

Other choices are `objectlink`, `healthfinding`, `alertrule`, `alertchannel`, `alertevent`. The response is a ZIP containing selected crypto material and metadata snapshots. Each type requires its existing export/download permission and view scope; keys require a superuser. A write-enabled token is required. Secrets from alert configuration are excluded. Metadata snapshots are not automatically recreated by the crypto importer.

All empty authorized material/metadata/inventory exports now return HTTP 200 JSON `{"warning": "There are no objects available to export with the current filters and permissions.", "count": 0}` without an attachment. Clients must inspect Content-Type before treating the response as ZIP. UI exports display the same warning as a page. Non-empty exports keep their normal formats.
