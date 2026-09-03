# Services

A Service represents a system, application, or endpoint that consumes certificate material.

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
- Certificate Policy
- owner
- tags
- custom fields
- description
- comments

`deployment` provides common UI suggestions and accepts custom values. `deployment_metadata` is a JSON object for deployment-specific details such as namespace, secret name, ingress, virtual host, configuration reference, or other platform metadata.

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
