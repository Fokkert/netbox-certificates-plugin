"""Compare installed NetBox models with migration files, without connecting to a database.

Run with NetBox's Python environment, for example:
python scripts/check_migration_state.py --netbox-root /opt/netbox
"""
import argparse
import os
from pathlib import Path
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--netbox-root", type=Path, required=True, help="NetBox checkout containing netbox/manage.py")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    netbox_path = args.netbox_root.resolve() / "netbox"
    if not (netbox_path / "manage.py").is_file():
        parser.error("--netbox-root must contain netbox/manage.py")
    sys.path[:0] = [str(netbox_path), str(root / "tests"), str(root)]
    # Use only the disposable test configuration. MigrationLoader(None) loads
    # migration files, not the installed database's applied-migration table.
    os.environ["NETBOX_CONFIGURATION"] = "netbox_configuration"
    os.environ["DJANGO_SETTINGS_MODULE"] = "netbox.settings"
    import django
    django.setup()
    from django.apps import apps
    from django.db.migrations.autodetector import MigrationAutodetector
    from django.db.migrations.loader import MigrationLoader
    from django.db.migrations.questioner import NonInteractiveMigrationQuestioner
    from django.db.migrations.state import ProjectState

    loader = MigrationLoader(None)
    changes = MigrationAutodetector(
        loader.project_state(), ProjectState.from_apps(apps),
        NonInteractiveMigrationQuestioner(specified_apps={"netbox_certificates"}, dry_run=True),
    ).changes(graph=loader.graph, trim_to_apps={"netbox_certificates"})
    pending = changes.get("netbox_certificates", [])
    for migration in pending:
        for operation in migration.operations:
            print(operation.describe())
    if pending:
        raise SystemExit("Plugin models differ from the published migration state.")
    print("No model/migration differences detected for netbox_certificates.")


if __name__ == "__main__":
    main()
