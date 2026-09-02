# Upgrade Notes

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

0.4.7 has no database migration and no new static asset. Replace the plugin source and restart both NetBox services.

## 0.4.5 -> 0.4.6

0.4.6 has no database migration and introduces no new static file. Replace the plugin source and restart both NetBox services.

## 0.4.4 -> 0.4.5

0.4.5 has no database migration and no new static assets.

Replace the plugin source, run `manage.py check`, and restart both NetBox and NetBox RQ services.

Retired 0.4.x compatibility routes are intentionally removed. Use the current `expiration-alerts/`, `expiration-alert-configurations/`, `expiration-alert-events/`, `certificates/expiration-summary/`, and `import-objects/` interfaces only.
