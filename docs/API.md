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
| `csrs/` | CSRS |
| `certificate-authorities/` | CA Certificates |
| `certificate-policies/` | Certificate Policies |
| `health-findings/` | Health Findings |
| `object-links/` | Object Links |
| `alert-rules/` | Alert Rules |
| `alert-channels/` | Alert Channels |
| `alert-events/` | Alert Events |

Standard NetBox REST list, retrieve, create, update, and delete behavior applies according to the model and ObjectPermissions.

## Certificate Authorities

`certificate-authorities/` returns Certificate objects whose parsed X.509 Basic Constraints mark them as CAS.

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

and an optional `policy`.

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

The API uses the same FilterSet architecture as the UI. Service and Policy relationships are available as filters on relevant inventory objects.

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
| GET | `{resource}/export-archive/` | Filtered metadata ZIP, including empty results |
| GET / POST | `{crypto-resource}/export-material/` | Filtered material ZIP; bundles require POST options |

Metadata resources: `groups`, `services`, `certificate-policies`, `health-findings`, `object-links`, `alert-rules`, `alert-channels`, `alert-events`. Crypto resources: `certificates`, `certificate-authorities`, `private-keys`, `csrs`, `bundles`. Query parameters use the resource's existing filters; display-only parameters are ignored. Metadata requires `archive_export` and view permission. Material requires `download` (or Bundle `export`), a write-enabled token, and a superuser when keys are included. PFX additionally requires Bundle `export_pfx`.

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
