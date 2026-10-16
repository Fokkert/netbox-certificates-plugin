# NetBox Certificates Plugin

Store certificates, encrypted private keys, CSRs, and bundles in NetBox. Organize them into typed Groups, link them to Services, inspect health findings, and send email or webhook alerts.

| Component | Supported |
| --- | --- |
| Release | 1.9.2 |
| NetBox | 4.5.9 and 4.5.10 |
| Python | 3.12+ |
| cryptography | 42+ |

The current release is **v1.9.2**. Older Git tags and the changelog remain as development history; previously published PyPI versions are unaffected. Install the version pinned below.

## Features

- X.509 metadata and cryptographic relationships calculated from imported material.
- CSR generation with a new or existing private key.
- Typed, hierarchical Groups and Services with linked certificates, keys, CSRs, and bundles.
- Dashboard combining inventory, expiration, health findings, filters, and bulk actions.
- Optional live Service certificate comparison, disabled by default, with a 14-day results graph and 90-day check history.
- Superuser-only private-key access history for material exports and CSR signing.
- HTML email and webhook alerts with per-certificate expiration triggers and configurable repeat timing.
- Content-detected material import, certificate chains, PFX export, and metadata backup/restore for Groups and Services.
- NetBox permissions, REST API, tags, custom fields, ownership, and configurable table columns.

## Navigation

```text
OVERVIEW
├── Dashboard
└── Preferences

INVENTORY
├── Groups
├── Services
├── Bundles
├── Certificates
├── Private Keys
└── CSRs

OPERATIONS
├── Generate CSR
├── Import Objects
└── Alerts Configuration
```

The standalone Backup and Restore page has been removed. Use the controls on the corresponding inventory pages.

## Dashboard

Inventory tiles link to each object list. Certificate Authorities opens Certificates filtered to `IS CA = true`. Expiration, assignment details, and finding filters are expanded by default and can be collapsed when needed. Run health scans, export findings, and use permission-controlled bulk actions from the same page.

Dashboard is at `/plugins/ssl-certificates/dashboard/`. Retired Vault, Health, Expiration Dashboard, CA-list, and policy URLs have been removed. Preferences controls list limits and optional sections. The layout follows NetBox's light or dark theme.

The live-check graph shows actual TLS attempts, matching fingerprints, mismatches, and failed connections. Page loads never initiate checks. Counts respect Service view permissions; superusers also see history for deleted Services. History begins after upgrading, with no invented historical data. Recent private-key access records show decryption during authenticated UI/API requests, including failures and response status, without storing key material. Only superusers can read this audit history.

## Services

A Service describes a certificate-consuming endpoint. Choose its protocol and deployment, enter a primary URL or hostname/port, and link its expected certificates or bundles. Certificates, private keys, CSRs, and bundles are selected together under Cryptographic artifacts.

Form group headings use NetBox's native size, spacing, and input-column alignment. The Deployment metadata field was removed in 1.9.1; use description, comments, or custom fields for additional Service details. Migration 0032 removes the field's saved values.

To check the certificate actually presented by a Service:

1. In **Alerts Configuration → When and what to send**, enable **Check live Service certificates for mismatches**.
2. Edit each Service and enable **Check live certificate** under Endpoints. The Service itself must also be enabled.
3. In **Preferences**, enable scheduled health scans and choose their frequency. Keep `netbox-rq` running. Use **Dashboard → Run health scan** for a manual check.
4. For notifications, enable alerts, configure email or webhook delivery, and select **Missing or mismatched certificates on services**.

Both check switches default off. With the global switch off, no endpoint connections occur, including during manual scans. The move from Preferences in 1.8.0 preserves its saved value.

The checker uses the primary URL host and explicit URL port, otherwise the Service hostname/port, with the configured protocol and SNI. It compares the presented leaf certificate's SHA-256 fingerprint against any linked certificate or bundle certificate. It supports HTTPS/TLS, LDAPS, SMTPS, IMAPS, POP3S, MQTTS, and PostgreSQL/MySQL TLS negotiation. No HTTP content, redirects, credentials, or additional URLs are requested. Private CA and expired certificates can be compared without CA trust validation. Connection failures are reported separately; an outage does not falsely resolve a previous mismatch.

## Health findings

Findings show severity, state, affected and related objects, evidence, and detection times. The scanner checks expiration, chains, certificate/key/CSR relationships, service names, duplicates, cryptographic requirements, and optional live endpoints. Findings can be acknowledged, ignored, or resolved using the applicable permissions.

Removing an alert category does not erase its historical findings or disable local cryptographic analysis. The **Weak or reused keys and outdated signatures** choice has been removed from the managed Alerts Configuration rule. Migration 0030 removes that saved category; if it was the rule's only selection, the rule is disabled rather than broadened to unrelated alerts. Separate advanced rules are retained.

## Alerts and Preferences

**Alerts Configuration** contains notification categories, the live Service-check switch, certificate requirements, repeat/cooldown timing, SMTP, and webhooks. **Preferences** contains scan/evaluation schedules, Dashboard limits/visibility, and import/CSR defaults. Both settings pages require a superuser.

Expiration notifications use each certificate's **Alert Trigger** and **Trigger Unit**, defaulting to **1 month**. Clear both to disable its expiration notifications. Set **Repeat unresolved alerts every (days)** to 7 for weekly reminders or 0 for one notification per occurrence. New problems can still notify immediately. Recovery notifications are separate.

Email uses HTML plus a plain-text alternative. Webhooks support POST, GET, PUT, PATCH, DELETE, HEAD, and OPTIONS. GET/HEAD/OPTIONS carry a `payload` query parameter; other methods send JSON. SMTP and webhook TLS verification can be disabled independently. Test buttons save the form and send a sample, even when that delivery method is disabled.

## Import, export, and restore

| Objects | Export | Import or restore |
| --- | --- | --- |
| Certificates, Private Keys, CSRs | Material export from the object/list | Import Objects detects PEM, DER, PKCS#7/CMS, PFX, and supported archives |
| Bundles | Separate material or PFX; optional password and chain | Import Objects rebuilds relationships from material |
| Services | Backup services on the Services list | Restore services merges names and available relationships |
| Groups | Backup groups on the Groups list | Restore groups merges names, hierarchy, and available memberships |
| Combined inventory | Export from Dashboard | Reimport material together; metadata merge API accepts Groups/Services |

Import material first when restoring to another NetBox, then restore Groups and Services. Missing relationships are skipped with warnings. These restores update matching names without deleting unrelated inventory. Export filters are honored; empty exports show a warning. Ordinary metadata exports exclude private keys and alert credentials. Other exported object metadata is reference-only, not a replacement backup.

Private-key material export and Groups/Services restores require a superuser. The retired full-snapshot APIs have been removed. See [Imports](docs/IMPORTS.md), [Exports](docs/EXPORTS.md), and [Groups and Services restore](docs/BACKUPS.md).

## Cryptographic information

CN/subject, SANs, fingerprints, validity, algorithms, CA status, issuer chains, artifact matches, and Supersedes are derived from material and cannot be manually edited. Import renewal/replacement material as a new object. Names, organizational metadata, and certificate alert timing remain editable.

Groups have a member type: Certificates, Private Keys, CSRs, Bundles, Services, or Groups. Legacy mixed groups retain their existing members. Table configuration offers safe metadata and relationship columns; secret material is not a selectable column.

## REST API

Base: `/api/plugins/ssl-certificates/`. Inventory endpoints include `certificates/`, `private-keys/`, `csrs/`, `bundles/`, `groups/`, `services/`, `health-findings/`, and `object-links/`.

Global settings use `alert-settings/` and `preferences/`. **`service_checks_enabled` now belongs to `alert-settings/`; submitting it to `preferences/` returns a migration message.** Per-Service opt-in remains `certificate_check_enabled` on `services/`. Settings mutations and sensitive operations require the appropriate permissions and a write-enabled API token. See [API reference](docs/API.md).

## Installation

For a new installation, add `netbox-certificates-plugin==1.9.2` to `/opt/netbox/local_requirements.txt`, enable the plugin in NetBox configuration, and provide a persistent Fernet key:

```python
PLUGINS = ["netbox_certificates"]  # Include your other plugins too.
PLUGINS_CONFIG = {
    "netbox_certificates": {"encryption_key": "YOUR_FERNET_KEY"},
}
```

Generate a key only for a new installation:

```bash
/opt/netbox/venv/bin/python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Install using pip, then migrate and collect assets:

```bash
sudo /opt/netbox/venv/bin/python -m pip install 'netbox-certificates-plugin==1.9.2'
cd /opt/netbox/netbox
sudo /opt/netbox/venv/bin/python manage.py migrate
sudo /opt/netbox/venv/bin/python manage.py collectstatic --no-input
sudo /opt/netbox/venv/bin/python manage.py check
sudo systemctl restart netbox netbox-rq
```

For an existing installation, back up the database and configuration, keep the existing encryption key, and follow [UPGRADE.md](UPGRADE.md). **Apply all pending migrations through `0032_remove_service_deployment_metadata`.** Do not generate or fake migrations on the VM.

## Security

Private keys and alert credentials are encrypted at rest. Secret material is excluded from ordinary API, GraphQL, search, and metadata exports. Sensitive downloads prevent caching, and material archives include checksums. Permission-scoped queries control object visibility and actions. Back up the encryption key with the database; replacing it makes existing secrets unreadable. See [SECURITY.md](SECURITY.md).

## Documentation

- [Upgrade](UPGRADE.md) and [Compatibility](COMPATIBILITY.md)
- [Services](docs/SERVICES.md), [Dashboard findings](docs/HEALTH-AND-VALIDITY.md), [Alerts](docs/ALERTS.md), and [Preferences](docs/PREFERENCES.md)
- [Imports](docs/IMPORTS.md), [Exports](docs/EXPORTS.md), and [Metadata restore](docs/BACKUPS.md)
- [API](docs/API.md), [Permissions](docs/PERMISSIONS.md), and [Bulk operations](docs/BULK_OPERATIONS.md)
- [Changelog](CHANGELOG.md), [Validation](VALIDATION.md), [Publishing](docs/PUBLISHING.md), and [Uninstall](docs/UNINSTALL.md)

## AI disclosure and disclaimer

This plugin's code is generated by AI (ChatGPT by OpenAI) under the maintainer's direction, including implementation, fixes, tests, and documentation. AI-generated code can contain errors, and passing tests does not guarantee correct or secure operation.

The plugin is provided **AS IS, without warranties or guarantees**. To the extent permitted by applicable law and the Apache-2.0 license, the maintainer and contributors disclaim responsibility and liability for problems, losses, damage, or other consequences arising from its use. The AI assistant provides no warranty or guarantee and assumes no responsibility for its operation. You are responsible for evaluating suitability, testing, backups, and deployment.

OpenAI does not maintain, sponsor, or endorse this project. This disclosure does not replace or expand the terms of the [Apache-2.0 license](LICENSE), including its warranty disclaimer and limitation of liability. See [AI_ASSISTANCE.md](AI_ASSISTANCE.md) and [NOTICE](NOTICE).

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
