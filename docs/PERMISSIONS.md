# Permissions

The plugin uses NetBox ObjectPermissions and standard model permissions.

## Standard actions

User-managed objects use:

```text
view
add
change
delete
```

Bulk operations apply the same ObjectPermission-restricted querysets.

## Cryptographic actions

| Object | Custom actions |
| --- | --- |
| Certificate | `download` |
| Private Key | `download` |
| CSR | `download` |
| Bundle | `export`, `export_pfx` |

Sensitive private-key operations retain the plugin's additional security checks beyond normal ObjectPermissions.

## Management actions

| Object | Custom actions |
| --- | --- |
| Service | `archive_export` |
| Certificate Policy | `archive_export` |
| Object Link | `archive_export` |
| Health Finding | `run_healthscan`, `acknowledge`, `ignore`, `resolve`, `archive_export` |
| Alert Channel | `test`, `archive_export` |
| Alert Rule | `test`, `archive_export` |
| Alert Event | `archive_export` |

Example Django permission codenames:

```text
netbox_certificates.run_healthscan_healthfinding
netbox_certificates.test_alertchannel
netbox_certificates.archive_export_service
```

On NetBox 4.5, custom plugin actions can be entered in ObjectPermission **Additional actions** when a dedicated checkbox is not displayed.

## ObjectLinks

ObjectLink create/change/delete requires ObjectLink permission and visibility of the referenced endpoints. Automatic links are read-only.
