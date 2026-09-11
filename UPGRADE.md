# Upgrade to 1.1.2

This revision upgrades 1.1.1 (or 1.1.0) in place on NetBox 4.5.9 or 4.5.10. No uninstall is needed. The commands below assume the standard `/opt/netbox` installation, local PostgreSQL database `netbox`, and systemd services `netbox` and `netbox-rq`. Adjust these names for your VM; Docker installations should rebuild their image instead.

## Before upgrading

Keep the existing `PLUGINS_CONFIG['netbox_certificates']['encryption_key']` unchanged. Back up PostgreSQL, NetBox configuration (including that key), and `/opt/netbox/local_requirements.txt`. A VM snapshot is also useful.

Run on the Linux VM, not on the development Windows computer:

```bash
sudo systemctl stop netbox netbox-rq
umask 077
sudo -u postgres pg_dump -Fc netbox > "$HOME/netbox-before-certificates-1.1.2.dump"
sudo cp -a /opt/netbox/local_requirements.txt /opt/netbox/local_requirements.txt.before-certificates-1.1.2
```

If the database is remote or has a different name, use your usual database backup command. Confirm the backup succeeded before continuing.

## Install the new package

After GitHub's release workflow has successfully published **1.1.2** to PyPI:

```bash
sudo /opt/netbox/venv/bin/python -m pip install --upgrade 'netbox-certificates-plugin==1.1.2'
```

If the GitHub tag exists but PyPI publication is still pending, pip can install directly from the tagged source archive, without copying files or cloning the repository:

```bash
sudo /opt/netbox/venv/bin/python -m pip install --upgrade 'https://github.com/Fokkert/netbox-certificates-plugin/archive/refs/tags/v1.1.2.zip'
```

Edit `/opt/netbox/local_requirements.txt` with `sudoedit` and replace the existing plugin entry with the following single line. This preserves the version when NetBox's upgrade script recreates its environment:

```text
netbox-certificates-plugin==1.1.2
```

Then run:

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

The installed version should be `1.1.2`. If a migration or check fails, investigate that error before restarting; do not skip it.

## After restarting

- Hard-refresh the browser to load the new static files.
- Open **Health and Validity**, inspect expiration counts and findings, and open a finding detail page.
- Expand a group, create and edit a subgroup, and check existing Service/artifact membership.
- Export a bundle as separate files and as PFX, with and without password protection and chain inclusion. Confirm `example.com's Bundle.zip` contains `example.com.pfx` in PFX mode.
- Open **Alerts Configuration** as a superuser. Existing settings and rules remain active; a new configuration starts disabled and accessible through the additional-rules link. Review them before enabling overlapping alerts.
- Use **Save and send test email** or **Save and send test webhook** to save and test the form, including when a delivery method is disabled. Turning off the appropriate **Verify TLS certificate** checkbox permits an untrusted destination certificate.
- NetBox's RQ worker must be running; the existing health/alert system job runs every 15 minutes. Repeat time `0` means once per occurrence, with a separate recovery notification if selected.

## Data migration

For an upgrade from 1.1.1, migration `0021_csr_plural_label` changes only the CSR display plural to **CSRs**. It preserves permissions and ordering and does not alter stored certificates, keys, groups, or alert settings.

For older installations:

Migration `0020_certificate_alert_defaults` defaults new certificate alerts to 1 month and initializes existing certificates only when both trigger fields were unset. Custom timing is retained. It also adds Group archive-export permission, sets the earlier CSR display label, and removes obsolete add permissions for generated findings/events. The earlier `0019_alert_settings` migration remains in the chain for older installations. Certificates, keys, CSRs, bundles, groups, services, policies, existing rules/channels, and delivery history are retained.

The one-time initialization enables per-certificate expiration timing for previously unconfigured certificates, but alerts still require an enabled rule and delivery channel. Existing rule-level `expiration_days` values are ignored. Review the two certificate columns after upgrading; clear both to disable expiration alerts for an individual certificate.

Non-superusers who export Groups need Additional action `archive_export` on Group, along with view permission. Custom-action ObjectPermission constraints now apply to the action itself as well as visibility.

## API and URL changes

| Existing interface | Behavior in 1.1.2 |
| --- | --- |
| `/expiration-dashboard/` | Redirects to combined `/health/` |
| `/alerts/` rule list | Single alert settings page (superuser) |
| Rule list | `/alerts/rules/` |
| Bundle material GET | Options form; submit POST to download |
| PFX API | `allow_unencrypted_pfx=true` explicitly permits an empty password |

SMTP/webhook API channels retain `smtp_verify_tls` and `webhook_verify_tls`, both true by default. Service JSON API fields retain their existing types; the UI accepts additional URLS one per line.

New endpoints cover CA-only import, singleton alert settings and sample tests, filtered metadata archives, and filtered material exports. See [API](docs/API.md). Empty authorized exports return valid archives, not 404 responses.

For upgrades from 0.5.0: `/inventory/` was replaced by `/vault/`, the legacy ArtifactLink API by `object-links/`, and CA identity resources by CA Certificate views. Legacy expiration-alert records remain stored but are not automatically converted; configure the new alert settings. The migration sequence retains older artifact data.

## Rollback

Stop NetBox and the worker, restore the pre-upgrade PostgreSQL backup and configuration/local requirements, reinstall `netbox-certificates-plugin==1.1.1`, run `manage.py collectstatic --no-input` and `manage.py check`, then restart. Keep the original encryption key. Reinstalling an older package alone does not roll back the database or changed alert settings.
