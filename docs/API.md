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
| `certificate-policies/` | Certificate Policies |
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
