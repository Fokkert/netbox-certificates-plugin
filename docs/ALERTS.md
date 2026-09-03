# Alerts

1.0 alerting is based on Health Findings instead of an expiration-only worker.

## Objects

### AlertChannel

A destination/transport.

Supported types:

- SMTP email
- webhook

Email channels configure SMTP host/port/username, TLS/SSL, sender and recipients. SMTP passwords are encrypted at rest.

Webhook URLs and headers are encrypted at rest.

### AlertRule

A rule scopes which findings are delivered and to which channels.

Every scope is optional. Available controls include:

- finding code;
- category;
- severity;
- finding status;
- object type;
- tag;
- owner;
- Service;
- Group;
- Certificate Policy;
- expiration-days threshold;
- cooldown;
- repeat interval;
- notification on recovery.

A rule can use multiple channels.

### AlertEvent

Records delivery attempts and their result.

## Expiration examples

A rule can request:

```text
category = validity
finding_code = CERT_EXPIRING
expiration_days = 30
severity = warning/medium/high
```

Another rule can use a different threshold, for example 120 days. The Health scan automatically extends its expiration horizon to ensure the configured threshold can be evaluated.

## Security

SMTP passwords, webhook URLs and webhook headers are never emitted in ordinary serializers, GraphQL or metadata archives.

Changing the plugin Fernet key without migrating encrypted data will make existing stored secrets/private keys undecryptable.

## Testing

AlertChannel and AlertRule expose permission-protected `test` actions in UI/API.

A channel test sends a neutral 1.0 test payload.

A rule test runs the configured rule against matching findings while bypassing the normal cooldown for that explicit test action.

## Background processing

The unified 1.0 system job:

1. refreshes established certificate validity/status fields;
2. refreshes Health Findings;
3. evaluates and dispatches Alert Rules.
