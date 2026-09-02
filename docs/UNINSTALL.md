# Removing the Plugin Completely

> **Destructive operation:** This procedure removes plugin database tables and therefore destroys all plugin Certificates, encrypted Private Keys, CSRs, Bundles, Groups, links, CA identities, expiration settings, and alert-event history. Take a PostgreSQL/VM backup and separately preserve the current plugin Fernet encryption key before continuing.

The safest order is to migrate the app to zero **while the plugin is still installed and enabled**, then disable/uninstall it.

## Phase A — backup and inventory

```bash
/opt/netbox/venv/bin/python -m pip show netbox-certificates-plugin || true
grep -n 'netbox-certificates\|netbox_certificates' /opt/netbox/local_requirements.txt || true
```

Back up PostgreSQL using your normal production process. Also preserve `PLUGINS_CONFIG['netbox_certificates']['encryption_key']` in protected secrets storage.

## Phase B — stop services and remove plugin data

```bash
sudo systemctl stop netbox netbox-rq

cd /opt/netbox
sudo -u netbox ./venv/bin/python ./netbox/manage.py migrate netbox_certificates zero
```

After the migration succeeds, remove plugin ObjectType references from ObjectPermissions without deleting unrelated permissions:

```bash
cd /opt/netbox
sudo -u netbox ./venv/bin/python ./netbox/manage.py shell <<'PY'
from core.models import ObjectType
from users.models import ObjectPermission

plugin_types = list(ObjectType.objects.filter(app_label="netbox_certificates"))

for permission in ObjectPermission.objects.filter(object_types__in=plugin_types).distinct():
    permission.object_types.remove(*plugin_types)
    if not permission.object_types.exists():
        permission.delete()

print(f"Removed references to {len(plugin_types)} plugin ObjectType(s).")
PY
```

## Phase C — disable plugin configuration

Edit the active NetBox `configuration.py` and remove `"netbox_certificates"` from `PLUGINS`, and remove its `PLUGINS_CONFIG` dictionary.

Also remove its package line from `/opt/netbox/local_requirements.txt`.

## Phase D — uninstall package and old manual-source deployment

```bash
sudo /opt/netbox/venv/bin/python -m pip uninstall -y netbox-certificates-plugin || true
sudo rm -rf /opt/netbox-plugins/netbox-certificates-plugin
```

If older `.old` deployment copies exist and you already have an external backup:

```bash
sudo find /opt/netbox-plugins -maxdepth 1 -type d \
  -name 'netbox-certificates-plugin*.old' \
  -print -exec rm -rf -- {} +
```

## Phase E — remove stale content types and rebuild static files

```bash
cd /opt/netbox
sudo -u netbox ./venv/bin/python ./netbox/manage.py remove_stale_contenttypes --no-input
sudo ./venv/bin/python ./netbox/manage.py collectstatic --clear --no-input
sudo -u netbox ./venv/bin/python ./netbox/manage.py check
```

## Phase F — verify it is gone

```bash
cd /opt/netbox

/opt/netbox/venv/bin/python -m pip show netbox-certificates-plugin && {
    echo "FAIL: distribution is still installed"
    false
} || true

sudo -u netbox ./venv/bin/python ./netbox/manage.py shell <<'PY'
from django.contrib.contenttypes.models import ContentType
from django.db import connection

with connection.cursor() as cursor:
    cursor.execute("SELECT count(*) FROM django_migrations WHERE app = %s", ["netbox_certificates"])
    migration_rows = cursor.fetchone()[0]
    cursor.execute("""
        SELECT count(*)
        FROM information_schema.tables
        WHERE table_schema = current_schema()
          AND table_name LIKE 'netbox_certificates_%'
    """)
    tables = cursor.fetchone()[0]

content_types = ContentType.objects.filter(app_label="netbox_certificates").count()
print({"migration_rows": migration_rows, "plugin_tables": tables, "content_types": content_types})
if any((migration_rows, tables, content_types)):
    raise SystemExit("Plugin residue still exists")
PY
```

Expected residue counts are all zero. Then:

```bash
sudo systemctl start netbox netbox-rq
sudo systemctl --no-pager --full status netbox netbox-rq
```

Do not proceed to a fresh installation until the zero-residue verification and `manage.py check` are clean.
