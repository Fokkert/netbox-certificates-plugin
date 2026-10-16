# Services

A Service represents a system, application, or endpoint that consumes certificate material.

## Quick setup

Choose a type, environment, deployment preset, and protocol. Enter a primary URL and select certificates or bundles. Leave port, hostname, and SNI blank to derive them from the URL and protocol. Additional URLs accept one URL per line. All fields stay visible, with certificates and private keys together. Existing custom deployment and protocol values remain selectable when editing.

## Metadata

Service fields include:

- name
- status
- type and optional custom type
- environment
- criticality
- deployment
- deployment metadata
- protocol
- primary URL
- additional URLs
- hostname
- port
- SNI name
- external reference
- contact
- enabled state
- owner
- tags
- custom fields
- description
- comments

`deployment` provides a dropdown of common technologies and a custom-name option. Deployment metadata was removed in 1.9.1. Use the Service description, comments, or NetBox custom fields for additional information.

## Relationships

Services support many-to-many relationships with:

- Groups
- Certificates
- Private Keys
- CSRs
- Bundles

The same cryptographic object can therefore be used by multiple Services, and one Service can reference multiple cryptographic objects.

## NetBox object links

ObjectLink connects Services and other plugin objects to native NetBox objects such as Devices, Virtual Machines, Interfaces, IP Addresses, Prefixes, Sites, Racks, Circuits, Clusters, VLANs, VRFs, and Tenants.

ObjectLinks are directional records with a relationship type and optional label. Automatic cryptographic links are read-only; manually created links are editable.

## Health checks

Service endpoint identities are derived from:

- SNI name
- hostname
- primary URL hostname
- additional URL hostnames

The Health engine compares these identities with linked Certificate SANs and reports uncovered names, mismatched keys/CSRs, private-key reuse, and suspicious non-wildcard certificate sharing.

## Editor layout

Every section is visible: Service, Endpoints, Cryptographic artifacts, Organization, and Metadata. Certificates and private keys are adjacent, followed by CSRs and bundles. There is no collapsible Advanced section. Additional URLs use one URL per line, and empty hostname/SNI/port fields derive from the primary URL and protocol.

Ports must be integers from 1 to 65535. Hostname/SNI and every endpoint URL are validated in the model, including API and bulk updates. Deployment metadata was removed in 1.9.1. Certificate requirements are configured globally in Alerts Configuration; Services no longer have policy assignments.

## Live certificate comparison

Enable **Alerts Configuration → Check live Service certificates for mismatches**, then **Check live certificate** in the Service's Endpoints section. The Service must be enabled and have a linked certificate or certificate-bearing bundle. Both switches default off; the global off switch prevents all endpoint connections. Scan scheduling remains in Preferences; Dashboard provides a manual scan button.

Only the primary URL (or hostname/port fallback) is probed, using the Service protocol and SNI. Additional URLs are used for local name-coverage checks only. The checker compares SHA-256 leaf-certificate fingerprints, accepts any linked certificate/bundle certificate, and reports connection failures separately. It sends no credentials or HTTP request. Direct TLS and PostgreSQL/MySQL TLS negotiation are supported. Private CA/expired certificates can be compared without CA trust validation. Alerts use the Service category and the existing repeat interval.

Use Backup services and Restore services on the Services list for metadata transfer. Restore merges names and skips missing relationships; it does not import private cryptographic material.
