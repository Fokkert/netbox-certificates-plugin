"""Verify 0024 -> 0025 on the disposable CI database, including stored statuses."""
import os


def main():
    if os.environ.get("NETBOX_CONFIGURATION") != "netbox_configuration" or os.environ.get("CI") != "true":
        raise SystemExit("This data-writing check must only run on the disposable CI database.")
    os.environ["DJANGO_SETTINGS_MODULE"] = "netbox.settings"
    import django
    django.setup()
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    previous = ("netbox_certificates", "0024_webhook_method")
    target = ("netbox_certificates", "0025_alertrule_statuses_default")
    executor = MigrationExecutor(connection)
    executor.migrate([previous])
    old_apps = executor.loader.project_state([previous]).apps
    old_rules = old_apps.get_model("netbox_certificates", "AlertRule")
    records = [old_rules.objects.create(name=f"migration-check-{index}", statuses=statuses)
               for index, statuses in enumerate(([], ["active"], ["acknowledged", "ignored"]))]
    ids = [record.pk for record in records]
    before = list(old_rules.objects.filter(pk__in=ids).order_by("pk").values())
    executor = MigrationExecutor(connection)
    executor.migrate([target])
    new_apps = executor.loader.project_state([target]).apps
    new_rules = new_apps.get_model("netbox_certificates", "AlertRule")
    after = list(new_rules.objects.filter(pk__in=ids).order_by("pk").values())
    if before != after:
        raise AssertionError("The repair changed stored alert rule data.")
    if new_rules._meta.get_field("statuses").get_default() != ["active"]:
        raise AssertionError("The default for new rules changed.")
    new_rules.objects.filter(pk__in=ids).delete()
    print("0024 -> 0025 preserves existing rules and the default for new rules.")


if __name__ == "__main__":
    main()
