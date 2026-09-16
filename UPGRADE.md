# Upgrade to 1.3.0

Upgrade 1.2.0 in place; older migrations remain available. Supported NetBox versions remain 4.5.9 and 4.5.10 with Python 3.12+. Run the following on the Linux VM. These commands assume `/opt/netbox`, PostgreSQL database `netbox`, and systemd units `netbox` and `netbox-rq`. Adapt paths/service names if your installation differs. Container deployments should install the pinned package when rebuilding their image.

## Preserve existing data

Keep the existing plugin Fernet encryption key unchanged. Back up the database, NetBox configuration including that key, and local requirements. Do not uninstall the plugin or delete its tables.

```bash
sudo systemctl stop netbox netbox-rq
umask 077
sudo -u postgres pg_dump -Fc netbox > "$HOME/netbox-before-certificates-1.3.0.dump"
sudo cp -a /opt/netbox/local_requirements.txt /opt/netbox/local_requirements.txt.before-certificates-1.3.0
```

Use your normal backup command if PostgreSQL is remote. Confirm the backup succeeded before continuing.

## Install with pip

Wait until GitHub Actions has successfully published 1.3.0 to PyPI. No source copying, cloning, or uninstall is needed:

```bash
sudo /opt/netbox/venv/bin/python -m pip install --upgrade 'netbox-certificates-plugin==1.3.0'
```

If the tag has been pushed but PyPI publication is pending, pip can instead install the tagged source archive:

```bash
sudo /opt/netbox/venv/bin/python -m pip install --upgrade 'https://github.com/Fokkert/netbox-certificates-plugin/archive/refs/tags/v1.3.0.zip'
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
lines.append('netbox-certificates-plugin==1.3.0')
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

The installed version must be `1.3.0`. Hard-refresh your browser after static files are collected.

## Data migration

`0023_preferences_and_derived_fields` adds Preferences with existing 15-minute scan/evaluation defaults and marks derived fields read-only. It preserves certificate/key/CSR material, delivery configuration, encryption keys, Groups, and Service assignments. The first health scan recalculates issuer and Supersedes relationships, including stale values that were previously entered manually. Names remain editable, including Bundle names. The migration repairs legacy mirrored links so their relationship, automatic flag, and enabled state match the internal engine; unverified historic manual cryptographic claims are disabled. Identifiable obsolete mirror rows are removed.

Open **Overview → Preferences** to adjust scheduling and defaults. Keep `netbox-rq` running: a five-minute worker cycle checks the configured intervals. Notification transports, certificate checks, and repeat/cooldown settings remain in **Alerts Configuration**. The Vault's CA card opens the filtered Certificates list; existing CA bookmarks redirect.

### Earlier migrations


`0022_global_certificate_checks` adds five fields to AlertSettings, retires Certificate Policy permissions, and adds Private Key `use` permission. When exactly one enabled policy exists, its supported settings are copied. With no enabled policy or several enabled policies, defaults apply; review **Alerts Configuration** after the upgrade. Unsupported historic RSA/validity values fall back to defaults. Algorithm/curve/issuer allowlists and CA eligibility are not converted into settings. Legacy policies and assignments remain stored privately but inactive.

Policy categories and explicit finding codes on rules are updated to the new configuration category/code. Existing policy scopes are inactive; other rule scopes continue. Review additional rules to avoid unexpectedly broad notification scope. The next health scan resolves obsolete policy findings. No certificate, key, CSR, or encryption key is rewritten.

Earlier migrations remain unchanged: 0021 fixes the CSRs label; 0020 defaults certificate expiration alerts to 1 month only where both fields were unset; 0019 creates the settings singleton. Clear both certificate trigger fields to disable its expiration alerts. Existing custom timing, delivery settings, and encrypted secrets are preserved.

## Verify after installation

- Delete disposable Certificates individually and with Delete Selected, including objects with automatic links; confirm dependent links are removed.
- Open Preferences, save a supported scan interval, and verify successful scheduled timestamps after the worker runs.
- Add/remove SAN rows, including IP addresses and URIs, and check the resulting CSR. Verify Group membership selections persist after saving.
- Verify derived fields and Supersedes are absent from edit forms and rejected by API updates; metadata remains editable.
- Open the CA card from the Vault and confirm the Certificates `IS CA` filter is applied.

- Open Alerts Configuration and review Certificate checks. Invalid email/port/header values should produce field errors. Use the sample email/webhook buttons to verify your destinations.
- Add, rename, move, and delete a disposable Group; inspect hierarchy spacing and existing membership.
- Generate a CSR using an existing key, and confirm the key count stays unchanged. Non-admin operators need Private Key `use` and view permissions plus CSR add and applicable Bundle permissions.
- Import a mixed batch, check deduplication and certificate/key/CSR/bundle/chain relationships, then export inventory. Empty list exports should show a warning.
- Confirm old encrypted material is still decryptable. Verify constrained accounts cannot access other objects or key material.
- Ensure `netbox-rq` is running for the periodic health/alert job.

## API and URL changes

| Interface | Current behavior |
| --- | --- |
| `preferences/` REST | New superuser-only GET/PATCH/PUT; mutations require a write-enabled token |
| CA UI bookmark | Redirects to Certificates with `is_ca=true`; REST CA routes remain compatible |
| Cryptographic writes | Derived fields rejected; replacement material must be imported as a new object |
| Policy UI bookmarks | Redirect to Alerts Configuration; writes unavailable |
| `certificate-policies/` REST and policy GraphQL | Retired |
| `alert-settings/` | Adds five global certificate check fields |
| `csrs/generate/` | Adds scoped `existing_private_key` selection |
| `import-objects/` | Mixed content detection, typed options, atomic deduplication/reconciliation |
| `export-inventory/` | New POST endpoint for selected material and metadata types |
| Empty exports | HTTP 200 warning, no attachment; API returns JSON with `count: 0` |

The older `/expiration-dashboard/` redirect to `/health/`, `/alerts/` settings page, and `/alerts/rules/` advanced rule list remain. For upgrades from 0.5.0, `/inventory/` was replaced by `/vault/` and legacy ArtifactLink REST by `object-links/`.

See [API](docs/API.md), [Permissions](docs/PERMISSIONS.md), and [Imports](docs/IMPORTS.md). Inventory export metadata snapshots are not a substitute for a full database backup or an automatic restoration of Services, Groups, and alert history.

## Rollback

Stop NetBox and the worker, restore the pre-upgrade database/configuration/local requirements backup, reinstall `netbox-certificates-plugin==1.2.0` using pip, run `collectstatic --no-input` and `check`, and restart. Keep the original encryption key. An older package alone does not undo database migrations or settings changes. If upgrading from an earlier version, reinstall the exact version represented by your backup instead.
