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
  ├─ Certificate Policy
  ├─ Certificates
  ├─ Private Keys
  ├─ CSRs
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
