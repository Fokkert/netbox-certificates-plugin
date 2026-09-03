# Upgrade to 1.0.0

Version 1.0.0 changes the plugin UI, API, relationship model, alerting model, and database schema.

## Before upgrading

Back up:

1. PostgreSQL
2. NetBox `configuration.py`
3. `/opt/netbox/local_requirements.txt`
4. the existing `netbox_certificates` Fernet encryption key

Keep the existing Fernet key. Replacing it will make previously encrypted private-key and alert-channel secrets unreadable.

## Data migration

The upgrade preserves existing:

- Groups
- Certificates
- Private Keys
- CSRs
- Bundles
- certificate-chain and root relationships

New tables are added for Services, Certificate Policies, Object Links, Health Findings, Alert Rules, Alert Channels, and Alert Events.

Legacy ArtifactLink records are migrated to ObjectLink where their endpoints can be resolved.

## API and URL changes

Applications or scripts using older plugin URLs must update them before deployment.

| Previous | 1.0.0 |
| --- | --- |
| `/inventory/` | `/vault/` |
| `/expiration-alerts/` | `/alerts/` |
| legacy ArtifactLink API | `object-links/` |
| legacy CA identity API | `certificate-authorities/` returning CA Certificate objects |
| expiration-only alert resources | `alert-rules/`, `alert-channels/`, `alert-events/` |

The old routes are not aliases in 1.0.0.

## Alert configuration

Existing expiration-alert database records are retained for data safety but are not converted automatically to Alert Rules and Alert Channels. Configure the required 1.0.0 channels and rules after the upgrade.

## Upgrade

Pin:

```text
netbox-certificates-plugin==1.0.4
```

Then run:

```bash
cd /opt/netbox
sudo ./upgrade.sh
```

Validate:

```bash
sudo -u netbox /opt/netbox/venv/bin/python /opt/netbox/netbox/manage.py check
/opt/netbox/venv/bin/python -m pip show netbox-certificates-plugin
```

Expected package version:

```text
Version: 1.0.4
```

Restart services:

```bash
sudo systemctl restart netbox netbox-rq
```

## Rollback

A database migrated to 1.0.0 should not be downgraded by installing 0.5.0 over it.

Rollback procedure:

1. stop NetBox
2. restore the pre-upgrade PostgreSQL backup
3. restore the previous `local_requirements.txt`
4. reinstall the previous plugin version
5. run `manage.py check`
6. restart NetBox and NetBox RQ
