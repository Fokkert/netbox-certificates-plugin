# Data Model

```text
ArtifactGroup
  ├─ child Groups
  ├─ Services
  ├─ Certificates
  ├─ Private Keys
  ├─ CSRs
  └─ Bundles

Service
  ├─ Certificates
  ├─ Private Keys
  ├─ CSRs
  └─ Bundles

Certificate
  ├─ parent/issuer relationships
  ├─ resolved root identity
  └─ Services

ObjectLink
  ├─ source ContentType + object ID
  └─ target ContentType + object ID

HealthFinding
  ├─ affected ContentType + object ID
  └─ optional related ContentType + object ID

AlertRule
  ├─ Alert Channels
  ├─ Services
  └─ Groups

AlertEvent
  ├─ Alert Rule
  ├─ Alert Channel
  └─ Health Finding
```

Generic object references use Django ContentType and GenericForeignKey. Public ObjectLink endpoints are restricted to public NetBox/plugin models.

Certificate `alert_trigger` defaults to `1`; `trigger_unit` defaults to `month`. They are a pair, can be cleared together, and control expiration alerts. The private `AlertSettings` singleton references the configured rule and email/webhook channels. `AlertRule.expiration_days` remains stored for compatibility but is ignored. Groups support direct artifact and Service membership in both their editor and REST API.

In 1.2.0, AlertSettings stores the five global certificate check fields. CertificatePolicy and its historic assignments remain private/inactive for data preservation. Private Key adds a scoped `use` action for CSR signing. No cryptographic material is rewritten by the migration.

## 1.3.0 derived fields and Preferences

AlertSettings also stores seven operational preferences and two last-success timestamps; it remains private. Migration 0023 adds these fields and marks parsed formats/statuses and Certificate/Bundle cryptographic relationships non-editable. Names and organizational metadata stay editable. Certificate/CSR/key material is immutable after creation through UI/API; renewal imports create new inventory objects and infer Supersedes.

Canonical serializers now cover all public models, so NetBox can serialize individual and cascaded deletes without an HTTP request. Deleting an artifact, Group, or Service removes its generic ObjectLinks. Certificate bulk deletion schedules one post-commit authority/renewal reconciliation per transaction.

The legacy link adapter maps `relation`, `origin`, `active`, and `note` explicitly. Migration 0023 repairs existing mirrors and disables unverified historic manual cryptographic claims.
