# Upgrade to 1.9.1

Upgrade 1.5.0 (or an earlier version) in place; older migrations remain available. Supported NetBox versions remain 4.5.9 and 4.5.10 with Python 3.12+. Run the following on the Linux VM. These commands assume `/opt/netbox`, PostgreSQL database `netbox`, and systemd units `netbox` and `netbox-rq`. Adapt paths/service names if your installation differs. Container deployments should install the pinned package when rebuilding their image.

## Preserve existing data

Keep the existing plugin Fernet encryption key unchanged. Back up the database, NetBox configuration including that key, and local requirements. Do not uninstall the plugin or delete its tables.

```bash
sudo systemctl stop netbox netbox-rq
umask 077
sudo -u postgres pg_dump -Fc netbox > "$HOME/netbox-before-certificates-1.9.1.dump"
sudo cp -a /opt/netbox/local_requirements.txt /opt/netbox/local_requirements.txt.before-certificates-1.9.1
```

Use your normal backup command if PostgreSQL is remote. Confirm the backup succeeded before continuing.

## Install with pip

Wait until GitHub Actions has successfully published 1.9.1 to PyPI. No source copying, cloning, or uninstall is needed:

```bash
sudo /opt/netbox/venv/bin/python -m pip install --upgrade 'netbox-certificates-plugin==1.9.1'
```

If the tag has been pushed but PyPI publication is pending, pip can instead install the tagged source archive:

```bash
sudo /opt/netbox/venv/bin/python -m pip install --upgrade 'https://github.com/Fokkert/netbox-certificates-plugin/archive/refs/tags/v1.9.1.zip'
```

Update the persistent package pin automatically so NetBox's upgrade script keeps this version:

```bash
sudo /opt/netbox/venv/bin/python - <<'PY'
from pathlib import Path
import re
path = Path('/opt/netbox/local_requirements.txt')
lines = path.read_text().splitlines() if path.exists() else []
pattern = re.compile(r'^\s*netbox[-_]certificates[-_]plugin(?:\[.*?\])?(?:\s|[=<>!~@]|$)', re.I)
lines = [line for line in lines if not pattern.match(line)]
lines.append('netbox-certificates-plugin==1.9.1')
path.write_text('\n'.join(lines) + '\n')
PY
```

Apply migrations and collect the new UI assets, then restart only if these checks succeed:

```bash
cd /opt/netbox/netbox
sudo /opt/netbox/venv/bin/python manage.py migrate
sudo /opt/netbox/venv/bin/python manage.py collectstatic --no-input
sudo /opt/netbox/venv/bin/python manage.py check
sudo /opt/netbox/venv/bin/python manage.py migrate --check
sudo /opt/netbox/venv/bin/python manage.py makemigrations --check --dry-run netbox_certificates
sudo /opt/netbox/venv/bin/python manage.py refresh_certificate_status
sudo /opt/netbox/venv/bin/python manage.py refresh_certificate_health
/opt/netbox/venv/bin/python -m pip show netbox-certificates-plugin
sudo systemctl start netbox netbox-rq
sudo systemctl status netbox netbox-rq --no-pager
```

The installed version must be `1.9.1`. Hard-refresh your browser after static files are collected.

## Changes in 1.9.1

**Migration `0032_remove_service_deployment_metadata` is required.** It removes the Service Deployment metadata field and its saved JSON values. Other Service data and relationships are preserved. Back up the database before upgrading if you need to retain those values; reversing the migration recreates an empty field, not its deleted contents.

Custom form group headings now follow NetBox's native size, input-column alignment, and spacing. Run `collectstatic` and hard-refresh your browser after upgrading. Deployment metadata is also removed from Service filters, table columns, exports, and the REST API; update clients that reference that field.

## Changes retained from 1.9.0

**Migration `0031_activity_and_retired_models` is required.** It creates Service check and private-key access history, and deletes retired CertificatePolicy, ExpiryAlertConfiguration, and ExpiryAlertEvent tables plus obsolete policy relationships and AlertRule.expiration_days. Current certificates, keys, CSRs, bundles, groups, services, findings, alert channels, rules, and settings are preserved. Back up the database before upgrading: removed legacy data cannot be recovered by reversing the migration.

Retired page redirects and the full-snapshot backup APIs are removed. Use Dashboard, the filtered Certificates list for CAs, and the existing inventory import/export controls. History starts at this upgrade. Run `collectstatic`, restart both services, and hard-refresh your browser.

## Changes retained from 1.8.0

**Migration `0030_retire_security_alert_option` is required.** It removes the retired security category from the managed settings rule. A managed rule selecting only that category is disabled instead of being broadened to unrelated notifications. Other categories, separate rules, inventory, and the saved Service-check switch are preserved. Reversing this migration does not restore removed selections.

The global Service check is now in **Alerts Configuration → Check live Service certificates for mismatches**. Per-Service opt-in and scan schedules are unchanged. API clients must send `service_checks_enabled` to `alert-settings/`, not `preferences/`.

Open **Overview → Dashboard** at `/plugins/ssl-certificates/dashboard/`. The old `/vault/` and health landing-page redirects were subsequently removed in 1.9.0. The standalone Backup and Restore page is removed. Use the Services/Groups list controls and artifact import/export actions; full-snapshot APIs were subsequently removed in 1.9.0.

The following sections describe earlier upgrade changes; current configuration locations are given above.

## Earlier migrations

All earlier migration files remain included. Upgrade in place and apply every pending migration. In particular:

- **0025** repairs the AlertRule statuses default without changing saved selections.
- **0026/0027** introduce typed Groups and repair recognizable generated artifact names. Existing mixed memberships and custom names are retained. These data repairs do not automatically reverse.
- **0028** adds Dashboard preferences with existing visibility and list-limit defaults.
- **0029** adds the global and per-Service live-check switches, both initially disabled. Existing saved values are preserved by 1.8.0.
- **0030** removes the retired alert category from the managed rule, as described above.

If an older installation reported unrecorded model changes, install this release and run the supplied migrations. Do not run `makemigrations` to generate new files or fake migrations on the VM. `manage.py` is a Python script; invoke it through the NetBox virtual environment as shown above.

Verify migration state:

```bash
cd /opt/netbox/netbox
sudo /opt/netbox/venv/bin/python manage.py showmigrations netbox_certificates
sudo /opt/netbox/venv/bin/python manage.py makemigrations --check --dry-run netbox_certificates
```

Every migration through `0032_remove_service_deployment_metadata` must show `[X]`, and the dry run must report no changes.

## API and URL changes

- `/dashboard/` is the canonical dashboard. `/vault/`, `/health/`, and `/expiration-dashboard/` are removed. The active finding-list return route `/health/findings/` still leads to Dashboard with filters preserved.
- The legacy `/inventory/` and `/inventory/<pk>/` hierarchy routes are not current interfaces; use Groups.
- `/backup/` and the full-snapshot API endpoints are removed. Services and Groups retain their own restore routes.
- `service_checks_enabled` is read/written through `alert-settings/`. The Preferences API rejects updates to the moved field instead of silently ignoring them.
- `object-links/` remains the API for links to NetBox objects. Automatic cryptographic links and derived fields remain protected from manual edits.
- The standalone Certificate Authorities page is replaced by a filtered Certificates list; CA import/export APIs remain available.

## After upgrading

Hard-refresh your browser after `collectstatic`. Confirm Dashboard, Groups, Services, Alerts Configuration, and Preferences load. For optional live checking, use Alerts Configuration and each Service's Endpoints controls; scheduling remains in Preferences. Test notification buttons send real samples and should only be used when wanted.

Keep `netbox-rq` running. A five-minute worker cycle evaluates the configured health and alert schedules. Alerts use existing per-certificate timing and repeat intervals. Import/export and scoped restore instructions are in [README](README.md) and [metadata restore](docs/BACKUPS.md).
