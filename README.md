# NetBox Certificates Plugin

NetBox Certificates Plugin adds certificate inventory and lifecycle management to NetBox. It manages X.509 certificates, encrypted private keys, CSRS, bundles, service relationships, certificate health, policy checks, alerting, imports, secure exports, and links to native NetBox objects.

## Compatibility

| Component | Supported |
| --- | --- |
| NetBox | 4.5.9, 4.5.10 |
| Python | 3.12+ |
| `cryptography` | 42+ |
| Release | 1.1.1 |
| Upgrade source | 1.1.0 (older migrations retained) |

## Features

- X.509 certificate inventory with parsed subject, issuer, SAN, validity, fingerprint, signature, key, and CA metadata
- encrypted private-key storage
- CSR inventory and generation
- certificate/key/CSR bundles with cryptographic identity validation
- Certificate Authorities view for imported CA certificates
- hierarchical Groups with expandable subgroups and visible member objects, plus selection for bulk operations
- Services for modeling certificate consumers and deployment metadata
- many-to-many Service relationships to Certificates, Private Keys, CSRS, Bundles, and Groups
- generic links from plugin objects to native NetBox objects such as Devices, VMs, Interfaces, IP Addresses, Sites, Circuits, VLANs, VRFs, Tenants, and Clusters
- Certificate Policies
- Health and Validity findings for expiration, chain problems, weak algorithms, duplicates, mismatches, orphaned objects, Service/SAN conflicts, and key reuse
- configurable SMTP and webhook alerts based on Health findings
- unified object import for PEM, DER, PKCS#7/CMS, PKCS#12/PFX, and supported archives
- NetBox-native filters, saved filters, metadata export, bulk edit, bulk delete, tags, custom fields, ownership, change logging, REST API, GraphQL, and global search
- secure material export with SHA-256 manifests

## Navigation

```text
OVERVIEW
├── Certificate Authorities
├── Cryptographic Vault
└── Health and Validity

INVENTORY
├── Groups
├── Services
├── Bundles
├── Certificates
├── Private Keys
└── CSRS

OPERATIONS
├── Import Objects
├── Generate CSR
└── Alerts Configuration
```

## Services

A Service represents a system or endpoint that consumes certificate material. Examples include websites, APIs, repositories, reverse proxies, load balancers, Kubernetes endpoints, mail systems, VPNs, databases, registries, and internal applications.

Service metadata includes status, type, environment, deployment, deployment metadata, protocol, URLS, hostname, port, SNI name, criticality, external reference, contact, owner, tags, custom fields, description, and comments.

`deployment` provides a dropdown of common technologies and a custom-name option. Protocols use dropdowns and default ports; a primary URL fills blank hostname/SNI/port fields. Additional URLS use one URL per line. All fields stay visible. Certificates, private keys, CSRS, and bundles share one Cryptographic artifacts section; organization, endpoints, and metadata have their own sections. `deployment_metadata` stores deployment-specific structured metadata such as a namespace, secret name, ingress name, virtual host, or configuration reference.

## Certificate Authorities

The Certificate Authorities view lists imported `Certificate` objects with X.509 `CA=true`, including roots, intermediates, and subordinate CAS. The dedicated **Import CA Certificates** action accepts only X.509 Basic Constraints `CA=true`. Leaf certificates, certificates without that extension, keys, CSRS, and mixed CA/non-CA uploads are rejected before saving anything. Root and chain resolution are maintained internally from certificate relationships.

## Cryptographic Vault

Cryptographic Vault uses a responsive, neutral layout with clickable inventory cards, service-assignment counts, and health categories. It provides a consolidated overview of Certificates, CA Certificates, Private Keys, CSRS, Bundles, Services, unassigned objects, and active Health findings.

## Health and Validity

The combined page shows expiration counts, upcoming/expired certificates, findings, filtering, policy access, and a health-scan action. The old Expiration Dashboard URL redirects here.

Health findings are persistent, searchable NetBox objects with severity, status, evidence, affected object, related object, and detection timestamps.

Checks include:

- certificate expiration and not-yet-valid state
- certificate-chain resolution and issuer validation
- expired or invalid issuers
- ambiguous issuers and chain loops
- weak RSA, elliptic-curve, DSA, and signature configurations
- duplicate Certificates, Private Keys, CSRS, and Bundles
- incomplete or mismatched Bundles
- orphaned private keys
- Certificate/Private Key/CSR relationship mismatches
- Service hostname, URL, and SNI coverage against certificate SANS
- private-key reuse across Services
- non-wildcard certificate reuse across unrelated Service endpoints
- Certificate Policy violations

## Certificate Policies

Policies can enforce certificate requirements such as minimum RSA size, permitted key and signature algorithms, permitted curves, maximum validity, SAN requirements, wildcard rules, CA eligibility, issuer restrictions, and private-key reuse policy.

Policies can be assigned to Services, Certificates, CSRS, and Bundles.

## Alerts

**Alerts Configuration** is a single settings page for superusers: choose email/webhook delivery, categories and severities, cooldowns, repeats, and recovery alerts. Expiration alerts follow each certificate’s **Alert Trigger** and **Trigger Unit**, defaulting to **1 month**. Both fields are available as certificate table columns. Clear both fields to disable expiration alerts for one certificate. Email and webhook TLS verification can be disabled independently for untrusted destinations. Existing rules remain available as advanced configuration.

Alert Rules select Health findings by code, category, severity, status, object type, tag, owner, Service, Group, or Policy. Global expiration thresholds are no longer used.

Alert Channels support SMTP and HTTP webhooks. SMTP passwords and webhook configuration are encrypted at rest with the plugin Fernet key.

The always-visible **Save and send test email** and **Save and send test webhook** buttons save the submitted configuration and send a sample even when delivery is disabled. Results appear on the settings page.

Alert Events record delivery results.

## Import

The unified importer supports:

- PEM and DER X.509 certificates
- private keys
- PKCS#10 CSRS
- PKCS#7/CMS containers
- PKCS#12/PFX
- supported archives
- multiple unrelated objects in one request
- multiple Bundle candidates grouped by matching public-key identity

Ambiguous cryptographic matches are rejected instead of guessed.

## Export

Bundle export opens an options form. Choose separate files or PFX, optional PFX password protection, and whether to include the chain. Single bundles support ZIP/TAR; bulk bundles use ZIP. Exporting private keys still requires a superuser.

NetBox-native export remains available for metadata tables.

Material export is available for Certificates, Private Keys, CSRS, Bundles, and CA Certificates. Multi-file exports include `manifest.json` with object identifiers, applied filters, filenames, SHA-256 checksums, and available cryptographic fingerprints.

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
certificate-policies/
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
netbox-certificates-plugin==1.1.1
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
- [Policies](docs/POLICIES.md)
- [Alerts](docs/ALERTS.md)
- [Exports](docs/EXPORTS.md)
- [Permissions](docs/PERMISSIONS.md)
- [Bulk Operations](docs/BULK_OPERATIONS.md)
- [Data Model](docs/MODELS.md)
- [Publishing](docs/PUBLISHING.md)
- [Uninstall](docs/UNINSTALL.md)
- [Validation](VALIDATION.md)

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

## Release 1.1.1

Empty material exports return a valid ZIP with a zero-count manifest; empty metadata exports also contain an empty `objects.json`. Invalid filters produce a readable validation error. See [API](docs/API.md) for CA-only import, alert settings and tests, and filtered export endpoints. New permission and migration details are in [Permissions](docs/PERMISSIONS.md) and [Upgrade](UPGRADE.md).
