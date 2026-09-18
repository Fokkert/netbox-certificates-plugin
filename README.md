# NetBox Certificates Plugin

NetBox Certificates Plugin adds certificate inventory and lifecycle management to NetBox. It manages X.509 certificates, encrypted private keys, CSRs, bundles, service relationships, certificate health, configurable checks, alerting, imports, secure exports, and links to native NetBox objects.

## Compatibility

| Component | Supported |
| --- | --- |
| NetBox | 4.5.9, 4.5.10 |
| Python | 3.12+ |
| `cryptography` | 42+ |
| Release | 1.3.3 |
| Upgrade source | 1.3.0 (older migrations retained) |

## Features

- X.509 certificate inventory with parsed subject, issuer, SAN, validity, fingerprint, signature, key, and CA metadata
- encrypted private-key storage
- CSR inventory and generation using a new or existing private key
- certificate/key/CSR bundles with cryptographic identity validation
- CA certificates accessible from the Vault through a filtered Certificates list
- hierarchical Groups with expandable subgroups and visible member objects, plus selection for bulk operations
- Services for modeling certificate consumers and deployment metadata
- many-to-many Service relationships to Certificates, Private Keys, CSRs, Bundles, and Groups
- generic links from plugin objects to native NetBox objects such as Devices, VMs, Interfaces, IP Addresses, Sites, Circuits, VLANs, VRFs, Tenants, and Clusters
- minimal global certificate checks within Alerts Configuration
- Health and Validity findings for expiration, chain problems, weak algorithms, duplicates, mismatches, orphaned objects, Service/SAN conflicts, and key reuse
- configurable SMTP and webhook alerts based on Health findings
- unified object import for PEM, DER, PKCS#7/CMS, PKCS#12/PFX, and supported archives
- NetBox-native filters, saved filters, metadata export, bulk edit, bulk delete, tags, custom fields, ownership, change logging, REST API, GraphQL, and global search
- secure material export with SHA-256 manifests

## Navigation

```text
OVERVIEW
├── Preferences
├── Cryptographic Vault
└── Health and Validity

INVENTORY
├── Groups
├── Services
├── Bundles
├── Certificates
├── Private Keys
└── CSRs

OPERATIONS
├── Import Objects
├── Generate CSR
└── Alerts Configuration
```

The Groups tree and Health findings have explicit Select all/Clear selection controls. Health can also select every filtered result across pages. Standard inventory tables retain NetBox's header checkbox and matching-query selection. Group membership uses one searchable NetBox multiple-choice selector per object type. Settings and export option forms remain responsive with a maximum width of 68rem.

## Services

A Service represents a system or endpoint that consumes certificate material. Examples include websites, APIs, repositories, reverse proxies, load balancers, Kubernetes endpoints, mail systems, VPNs, databases, registries, and internal applications.

Service metadata includes status, type, environment, deployment, deployment metadata, protocol, URLs, hostname, port, SNI name, criticality, external reference, contact, owner, tags, custom fields, description, and comments.

`deployment` provides a dropdown of common technologies and a custom-name option. Protocols use dropdowns and default ports; a primary URL fills blank hostname/SNI/port fields. Additional URLs use one URL per line. All fields stay visible. Certificates, private keys, CSRs, and bundles share one Cryptographic artifacts section; organization, endpoints, and metadata have their own sections. `deployment_metadata` stores deployment-specific structured metadata such as a namespace, secret name, ingress name, virtual host, or configuration reference.

## Certificate Authorities

Select **Certificate Authorities** in the Cryptographic Vault to open Certificates filtered to X.509 `CA=true`, including roots, intermediates, and subordinate CAs. The separate CA page has been removed; its old URL redirects to this filtered list. The dedicated **Import CA Certificates** action accepts only X.509 Basic Constraints `CA=true`. Leaf certificates, certificates without that extension, keys, CSRs, and mixed CA/non-CA uploads are rejected before saving anything. Root and chain resolution are maintained internally from certificate relationships.

## Cryptographic Vault

Cryptographic Vault uses a responsive, neutral layout with clickable inventory cards, service-assignment counts, and health categories. It provides a consolidated overview of Certificates, CA Certificates, Private Keys, CSRs, Bundles, Services, unassigned objects, and active Health findings.

## Preferences

**Overview → Preferences** lets superusers configure health scanning, independent alert evaluation intervals, upcoming-expiration findings, chain/archive import defaults, and the default RSA size for new CSR keys. Scan and alert intervals default to 15 minutes and support 5 minutes through 24 hours. Notification destinations, TLS options, certificate checks, and repeat rules remain in Alerts Configuration. See [Preferences](docs/PREFERENCES.md).

## Health and Validity

The combined page shows expiration counts, upcoming/expired certificates, findings, filtering and a health-scan action. The old Expiration Dashboard URL redirects here.

Health findings are persistent, searchable NetBox objects with severity, status, evidence, affected object, related object, and detection timestamps.

Checks include:

- certificate expiration and not-yet-valid state
- certificate-chain resolution and issuer validation
- expired or invalid issuers
- ambiguous issuers and chain loops
- weak RSA, elliptic-curve, DSA, and signature configurations
- duplicate Certificates, Private Keys, CSRs, and Bundles
- incomplete or mismatched Bundles
- orphaned private keys
- Certificate/Private Key/CSR relationship mismatches
- Service hostname, URL, and SNI coverage against certificate SANs
- private-key reuse across Services
- non-wildcard certificate reuse across unrelated Service endpoints
- configured certificate requirement violations

## Cryptographic information

Subjects (including CN), SANs, fingerprints, validity, algorithms, CA status, issuer chains, artifact matches, and Supersedes are calculated from stored material. These values cannot be edited in forms or the API. Existing certificate, CSR, and private-key material is immutable; import replacement material as a new object. Names, descriptions, Groups, Services, and per-certificate alert timing remain editable. CSR generation accepts the requested subject and SANs before signing; the resulting CSR attributes are parsed from the signed request.

## Certificate checks

Set minimum RSA size, optional maximum validity, SAN requirements, wildcard allowance, and key reuse handling directly in **Alerts Configuration**. These global settings apply to Certificates and CSRs; no separate policy definitions or assignments are needed. The settings are evaluated by health scans and violations can be selected as an alert category.

## Alerts

**Alerts Configuration** is a single settings page for superusers: choose email/webhook delivery, categories and severities, cooldowns, repeats, and recovery alerts. Expiration alerts follow each certificate’s **Alert Trigger** and **Trigger Unit**, defaulting to **1 month**. Both fields are available as certificate table columns. Clear both fields to disable expiration alerts for one certificate. Email and webhook TLS verification can be disabled independently for untrusted destinations. Existing rules remain available as advanced configuration.

Alert Rules select Health findings by code, category, severity, status, object type, tag, owner, Service or Group. Global expiration thresholds are no longer used.

Alert Channels support HTML email via SMTP and HTTP webhooks with POST (default), GET, PUT, PATCH, DELETE, HEAD, or OPTIONS. GET/HEAD/OPTIONS send the JSON payload in a `payload` query parameter; the other methods send a JSON body. Test notifications use the selected method too. SMTP passwords and webhook configuration are encrypted at rest with the plugin Fernet key.

The always-visible **Save and send test email** and **Save and send test webhook** buttons save the submitted configuration and send a sample even when delivery is disabled. Results appear on the settings page.

Alert Events record delivery results.

## Import

The unified importer supports:

- PEM and DER X.509 certificates
- private keys
- PKCS#10 CSRs
- PKCS#7/CMS containers
- PKCS#12/PFX
- supported archives
- multiple unrelated objects in one request
- multiple Bundle candidates grouped by matching public-key identity

Files are detected by content. Mixed uploads are validated before any writes, deduplicated by cryptographic identity, and linked after the complete batch is stored. Certificates, keys, CSRs, and bundles can be imported together across multiple archives. Invalid input or insufficient permissions rolls back the batch. The CA-only action rejects all non-CA content.

Limits are 64 MiB combined upload, 128 MiB expanded content, 10,000 counted files/objects, and three archive levels. See [Imports](docs/IMPORTS.md) for permissions, duplicate handling, relationship matching, and archive limits.

## Export

Bundle export opens an options form. Choose separate files or PFX, optional PFX password protection, and whether to include the chain. Single bundles support ZIP/TAR; bulk bundles use ZIP. Exporting private keys still requires a superuser.

**Export inventory** in the Vault downloads selected object types together as one ZIP. It includes material for Certificates, Private Keys, CSRs, and Bundles and can include metadata for Groups, Services, Object Links, Health findings, and alert objects. Cryptographic files can be reimported together; metadata snapshots are for reference, not a replacement for a database backup.

NetBox-native export remains available for metadata tables. Empty exports show a warning; the API returns HTTP 200 with a warning and `count: 0`, without an attachment.

Material export is available for Certificates, Private Keys, CSRs, Bundles, and CA Certificates. Multi-file exports include `manifest.json` with object identifiers, applied filters, filenames, SHA-256 checksums, and available cryptographic fingerprints.

Private-key material is decrypted only for authorized downloads and is never included in ordinary metadata serializers, search indexes, filters, GraphQL metadata, or metadata archives.

## REST API

Base path:

```text
/api/plugins/ssl-certificates/
```

Primary endpoints:

```text
groups/
services/
bundles/
certificates/
private-keys/
csrs/
certificate-authorities/
health-findings/
object-links/
alert-rules/
alert-channels/
alert-events/
```

See [docs/API.md](docs/API.md).

## Installation

Add the package to `/opt/netbox/local_requirements.txt`:

```text
netbox-certificates-plugin==1.3.3
```

Enable the plugin:

```python
PLUGINS = [
    "netbox_certificates",
]

PLUGINS_CONFIG = {
    "netbox_certificates": {
        "encryption_key": "YOUR_FERNET_KEY",
    },
}
```

Generate a Fernet key for a new installation:

```bash
/opt/netbox/venv/bin/python - <<'PY'
from cryptography.fernet import Fernet
print(Fernet.generate_key().decode())
PY
```

Run the standard NetBox upgrade:

```bash
cd /opt/netbox
sudo ./upgrade.sh
```

Verify:

```bash
sudo -u netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py check
sudo systemctl restart netbox netbox-rq
```

For upgrades from 1.0.5 or older versions, keep the existing Fernet key and read [UPGRADE.md](UPGRADE.md) before deployment.

## Security

- private keys are encrypted at rest
- SMTP passwords and webhook configuration are encrypted at rest
- decrypted private-key material is excluded from normal API, GraphQL, search, filtering, and metadata exports
- sensitive download responses use cache-prevention headers
- multi-file exports include SHA-256 manifests
- ObjectLinks are restricted to public NetBox/plugin models
- sensitive material operations retain additional permission checks

See [SECURITY.md](SECURITY.md).

## Documentation

- [Upgrade](UPGRADE.md)
- [Compatibility](COMPATIBILITY.md)
- [API](docs/API.md)
- [Services](docs/SERVICES.md)
- [Health and Validity](docs/HEALTH-AND-VALIDITY.md)
- [Retired policy migration](docs/POLICIES.md)
- [Imports](docs/IMPORTS.md)
- [Alerts](docs/ALERTS.md)
- [Preferences](docs/PREFERENCES.md)
- [Exports](docs/EXPORTS.md)
- [Permissions](docs/PERMISSIONS.md)
- [Bulk Operations](docs/BULK_OPERATIONS.md)
- [Data Model](docs/MODELS.md)
- [Publishing](docs/PUBLISHING.md)
- [Uninstall](docs/UNINSTALL.md)
- [Validation](VALIDATION.md)

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

## Release 1.3.3

This release fixes clearing Health filters, labels the query field Search, and shows invalid filter errors with a working reset link. Severity/status filters support multiple values consistently in the UI, API, and exports. Groups uses simpler tree rows and preserves expansion preferences during search. CSR generation uses consistent sections and preserves lowercase SAN types on redisplay. Editing resolved findings retains their resolution timestamp. No new database migration or permission definition is required. See [Upgrade](UPGRADE.md) for pip-only deployment and [Validation](VALIDATION.md) for checks and runtime limitations.
