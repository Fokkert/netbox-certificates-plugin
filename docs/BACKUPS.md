# Backup, restore, and metadata import

Open **SSL Certificates → Operations → Backup and Restore**. All three operations require an active NetBox superuser. API calls additionally require a write-enabled NetBox API token; session-only API requests are rejected.

## Full backup

Download a complete snapshot of all plugin database models, including certificates, private keys, CSRs, Bundles and retained archives, group hierarchy/memberships, Services, links, health findings, preferences, alert rules/channels/history, and retained legacy plugin configuration.

The optional password protects the entire ZIP using AES-256-GCM with a random salt/nonce and scrypt (N=32768, r=8, p=1). The encrypted `.nbcbak` file is a plugin format, not a password-protected ZIP understood by desktop ZIP programs. Without a password, the `.zip` contains readable secrets. Both formats contain private keys and alert delivery credentials; protect them accordingly. Passwords are never stored in the database.

Database-encrypted values are decrypted for export and encrypted with the destination's configured plugin Fernet key on restore. You do not need to copy the source NetBox encryption key to a different installation. The destination must already have a valid encryption key.

Backups are limited to 64 MiB as uploaded/downloaded and 128 MiB of expanded JSON. An oversized export fails without returning a truncated backup. The operation runs synchronously and briefly blocks plugin writes while collecting a consistent database snapshot.

## Full restore replaces existing plugin data

Install the **same plugin version** on a supported destination NetBox first. Restore the backup and then upgrade the plugin normally if needed. Matching versions ensure every stored field has the same meaning.

**Restoring erases all existing SSL Certificates plugin data and replaces it with the snapshot.** Download a current backup first. Type `REPLACE ALL PLUGIN DATA` in the confirmation field. The API requires that exact confirmation too. Wrong passwords, corrupted archives, invalid object values, and failed relationships abort the operation; database changes roll back as one transaction. Restore does not send a test notification, but restored delivery settings and history apply to subsequent scheduled alert checks.

Plugin primary keys are remapped, and generic links/health-finding identities are adjusted. This prevents the backup's database IDs from accidentally selecting unrelated destination objects. Cryptographic metadata is parsed from the restored material. Only restore files from trusted sources.

This is a **plugin data backup**, not a backup of the entire NetBox server. Other NetBox inventory, user accounts, permission definitions, tags, custom-field definitions, attachments from other plugins, server configuration, jobs, and NetBox's audit log are outside its scope. Existing external references are matched by portable identifiers (slug, username, name, or content-type natural key); missing or ambiguous matches are omitted and reported. A record requiring a missing external object is skipped. Target custom-field requirements must be compatible; invalid required values abort restore. Provision tags/custom fields on the destination before restoring if you need them retained.

## Merge Groups and Services exports

Use **Import Groups and Services** for existing Groups/Services archive exports or an Inventory ZIP containing their JSON. This operation creates missing objects and updates objects with matching names without erasing the other inventory. Import artifact material first if you want memberships resolved immediately. Missing certificate/key/CSR/Bundle/group references are skipped with warnings; available relationships are restored. Typed membership constraints and service value validation still apply.

New exports carry relationship names/fingerprints for cross-installation matching. Older exports containing only numeric IDs can restore names and editable properties, but cannot reliably identify relationships on another NetBox; those relationships are left unresolved instead of guessing. The metadata operation does not import artifacts, credentials, health findings, or alert settings; use material import or full restore for those.

## API

The base path is `/api/plugins/ssl-certificates/` (the plugin's configured API URL). Use your installation's API root if different.

| Endpoint (POST) | Request | Response |
| --- | --- | --- |
| `backup/export/` | JSON: optional `password` (empty means no encryption) | Binary `.zip` or `.nbcbak` download |
| `backup/restore/` | Multipart: `upload`, optional `password`, `confirmation=REPLACE ALL PLUGIN DATA` | JSON: `restored` count and `warnings` |
| `import-metadata/` | Multipart: `upload` | JSON: `imported` count and `warnings` |

Example without password protection (the downloaded ZIP contains secrets):

```bash
curl --fail-with-body -X POST \
  -H "Authorization: Token $NETBOX_TOKEN" \
  -H 'Content-Type: application/json' -d '{}' \
  "$NETBOX_URL/api/plugins/ssl-certificates/backup/export/" \
  -o plugin-backup.zip
```

Destructive restore:

```bash
curl --fail-with-body -X POST \
  -H "Authorization: Token $NETBOX_TOKEN" \
  -F 'upload=@plugin-backup.zip' \
  -F 'confirmation=REPLACE ALL PLUGIN DATA' \
  "$NETBOX_URL/api/plugins/ssl-certificates/backup/restore/"
```

Merge a metadata archive:

```bash
curl --fail-with-body -X POST \
  -H "Authorization: Token $NETBOX_TOKEN" \
  -F 'upload=@groups-export.zip' \
  "$NETBOX_URL/api/plugins/ssl-certificates/import-metadata/"
```
