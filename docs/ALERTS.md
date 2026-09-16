# Alerts

1.0 alerting is based on Health Findings instead of an expiration-only worker.

## Settings page

Open Alerts Configuration as a superuser. Select problem categories and severities, cooldown, repeats, and recovery notifications. Configure email and/or webhook delivery. **Save and send test email** and **Save and send test webhook** are available even before alerts are enabled. They save the form, validate the selected destination, send a sample, and display success or a sanitized connection/delivery error. Testing does not enable a disabled delivery method. SMTP supports STARTTLS, implicit TLS, or no TLS. SMTP and webhook certificate verification are enabled by default and independently configurable.

A zero repeat interval means once per occurrence. Recovery notifications are separate and sent once; recurrence starts a new occurrence. Delivery follows the 15-minute NetBox system job cycle.

Existing rules and channels are preserved. The page reports additional enabled rules; review those to avoid duplicate notifications. The enable switch controls the settings-page rule.

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
- cooldown;
- repeat interval;
- notification on recovery.

A rule can use multiple channels.

### AlertEvent

Records delivery attempts and their result.

## Per-certificate expiration timing

Set **Alert Trigger = 1** and **Trigger Unit = Month** for a one-calendar-month lead time. New certificates default to this pair. Migration 0020 also initializes existing certificates when both fields were unset, preserving custom timing. Both columns are visible by default and can be selected in the certificate table configuration.

For an alert 120 days before expiry, set that certificate's trigger to `120` and unit to `day`. For seven days, use `7` and `day`. Clear both fields to disable expiration and expired-certificate alerts for that certificate; other health problems can still alert. One month uses calendar arithmetic with month-end clamping, not a fixed 30-day approximation.

Health continues to show the normal 90-day expiration overview and creates earlier findings when a certificate's own trigger is due. Delivery checks the current certificate fields at the exact timestamp, independently of the rule's category/severity filters and repeat timing. Existing `AlertRule.expiration_days` values remain stored for compatibility but are ignored and removed from forms, table columns, filters, and the REST serializer.

## Security

SMTP passwords, webhook URLs and webhook headers are never emitted in ordinary serializers, GraphQL or metadata archives.

Changing the plugin Fernet key without migrating encrypted data will make existing stored secrets/private keys undecryptable.

## Testing

AlertChannel and AlertRule expose permission-protected `test` actions in UI/API.

A channel test sends a neutral test payload with the current plugin version.

A rule test runs the configured rule against matching findings while bypassing the normal cooldown for that explicit test action.

## Background processing

The unified 1.0 system job:

1. refreshes established certificate validity/status fields;
2. refreshes Health Findings;
3. evaluates and dispatches Alert Rules.

## Certificate checks in 1.2.0

The settings page also defines the five global certificate requirements described in [Retired policy migration](POLICIES.md). These settings affect Health findings, independently of whether notification delivery is enabled. Expiration timing remains per certificate; no global expiration threshold is added.

Invalid email addresses, SMTP hostnames and ports, webhook URLs/headers, and timing values are rejected even for disabled destinations. Clear webhook headers by submitting `{}`; leave the field blank to retain stored headers. Test buttons use the same validation before saving and sending the sample.
