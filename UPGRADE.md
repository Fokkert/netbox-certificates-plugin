# Upgrade Notes

## 0.4.11 -> 0.5.0

0.5.0 has **no database schema migration**. The `CertificateAuthority` model and certificate-chain relationships remain intact.

This feature release:

- adds multi-Bundle batch import for multiple uploaded archives and multiple loose identity sets;
- adds protected bulk cryptographic-material export on the Certificates, Private Keys, CSRs, and Bundles pages;
- retires the dedicated Certificate Authorities web page/navigation while retaining root-CA identity resolution and the read-only REST API;
- redirects legacy Certificate Authority web URLs to filtered Certificate inventory views.

Back up the NetBox database and the plugin encryption key before any production upgrade. Update the pinned package version in `/opt/netbox/local_requirements.txt`, run NetBox's normal `upgrade.sh`, run `manage.py check`, and restart NetBox and NetBox RQ.

Because bulk Private Key and Bundle material exports can contain plaintext private-key material, review `download_privatekey` and `export_bundle` ObjectPermissions before enabling the release for operators.

## 0.4.10 -> 0.4.11

0.4.11 has no database migration and no new static asset. Replace the plugin source, run `manage.py check`, and restart NetBox and NetBox RQ. This release fixes direct REST creation of Certificate and CSR objects with valid PEM material under NetBox 4.5.x model validation.

## 0.4.9 -> 0.4.10

0.4.10 has no database migration and no new static asset. Replace the plugin source, run `manage.py check`, and restart NetBox and NetBox RQ. This release corrects unified-import API validation status codes: invalid cryptographic combinations now return HTTP 400 rather than HTTP 500.

## 0.4.8 -> 0.4.9

0.4.9 has no database migration and no new static asset. Replace the plugin source, run `manage.py check`, and restart NetBox and NetBox RQ. This release fixes ordering for the expiration-alert configuration REST API queryset.

## 0.4.7 -> 0.4.9

0.4.9 has no database migration and no new static asset. Replace the plugin source, run `manage.py check`, and restart NetBox and NetBox RQ.

The release corrects only the CSR SAN Type dropdown initialization introduced in 0.4.7.

## 0.4.6 -> 0.4.7

0.4.7 has no database migration and introduces no new static asset. Replace the plugin source and restart both NetBox services.

## 0.4.5 -> 0.4.6

0.4.6 has no database migration and introduces no new static file. Replace the plugin source and restart both NetBox services.

## 0.4.4 -> 0.4.5

0.4.5 has no database migration and no new static assets.

Replace the plugin source, run `manage.py check`, and restart both NetBox and NetBox RQ services.

Retired 0.4.x compatibility routes are intentionally removed. Use the current `expiration-alerts/`, `expiration-alert-configurations/`, `expiration-alert-events/`, `certificates/expiration-summary/`, and `import-objects/` interfaces only.
