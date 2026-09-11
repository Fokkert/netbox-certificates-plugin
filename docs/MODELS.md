# Data Model

```text
ArtifactGroup
  ├─ child Groups
  ├─ Services
  ├─ Certificates
  ├─ Private Keys
  ├─ CSRS
  └─ Bundles

Service
  ├─ Certificate Policy
  ├─ Certificates
  ├─ Private Keys
  ├─ CSRS
  └─ Bundles

Certificate
  ├─ parent/issuer relationships
  ├─ resolved root identity
  ├─ Services
  └─ Certificate Policies

ObjectLink
  ├─ source ContentType + object ID
  └─ target ContentType + object ID

HealthFinding
  ├─ affected ContentType + object ID
  └─ optional related ContentType + object ID

AlertRule
  ├─ Alert Channels
  ├─ Services
  ├─ Groups
  └─ Certificate Policies

AlertEvent
  ├─ Alert Rule
  ├─ Alert Channel
  └─ Health Finding
```

Generic object references use Django ContentType and GenericForeignKey. Public ObjectLink endpoints are restricted to public NetBox/plugin models.

Certificate `alert_trigger` defaults to `1`; `trigger_unit` defaults to `month`. They are a pair, can be cleared together, and control expiration alerts. The private `AlertSettings` singleton references the configured rule and email/webhook channels. `AlertRule.expiration_days` remains stored for compatibility but is ignored. Groups support direct artifact and Service membership in both their editor and REST API.
