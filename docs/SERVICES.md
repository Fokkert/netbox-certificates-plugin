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

`deployment` provides common a dropdown of common technologies and a custom-name option. `deployment_metadata` is a JSON object for deployment-specific details such as namespace, secret name, ingress, virtual host, configuration reference, or other platform metadata.

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

Ports must be integers from 1 to 65535. Hostname/SNI and every endpoint URL are validated in the model, including API and bulk updates. Deployment metadata must be a JSON object. Certificate requirements are configured globally in Alerts Configuration; Services no longer have policy assignments.
