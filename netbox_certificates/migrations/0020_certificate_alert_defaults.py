from django.db import migrations, models


def initialize_alert_timing(apps, schema_editor):
    Certificate = apps.get_model("netbox_certificates", "Certificate")
    Certificate.objects.using(schema_editor.connection.alias).filter(
        trigger_unit="", alert_trigger__isnull=True,
    ).update(trigger_unit="month", alert_trigger=1)


def remove_generated_object_add_permissions(apps, schema_editor):
    apps.get_model("auth", "Permission").objects.using(schema_editor.connection.alias).filter(
        content_type__app_label="netbox_certificates", codename__in=("add_healthfinding", "add_alertevent"),
    ).delete()


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0019_alert_settings")]
    operations = [
        migrations.AlterModelOptions(name="artifactgroup", options={"ordering": ("name",), "verbose_name": "group", "verbose_name_plural": "groups", "permissions": (("archive_export_artifactgroup", "Can archive-export groups"),)}),
        migrations.AlterField(
            model_name="certificate", name="trigger_unit",
            field=models.CharField(blank=True, default="month", max_length=16, verbose_name="Trigger Unit",
                                   choices=[("year", "Year"), ("month", "Month"), ("week", "Week"), ("day", "Day"),
                                            ("hour", "Hour"), ("minute", "Minute"), ("second", "Second")]),
        ),
        migrations.AlterField(
            model_name="certificate", name="alert_trigger",
            field=models.PositiveIntegerField(blank=True, null=True, default=1, verbose_name="Alert Trigger"),
        ),
        migrations.AlterModelOptions(name="csr", options={"ordering": ("name",), "verbose_name": "CSR", "verbose_name_plural": "CSRS", "permissions": (("download_csr", "Can download CSR material"),)}),
        migrations.AlterModelOptions(name="healthfinding", options={
            "ordering": ("status", "-severity", "-last_detected"), "default_permissions": ("view", "change", "delete"),
            "permissions": (("run_healthscan_healthfinding", "Can run certificate health scans"),
                            ("acknowledge_healthfinding", "Can acknowledge health findings"),
                            ("ignore_healthfinding", "Can ignore health findings"),
                            ("resolve_healthfinding", "Can resolve health findings"),
                            ("archive_export_healthfinding", "Can archive-export health findings")),
        }),
        migrations.AlterModelOptions(name="alertevent", options={
            "ordering": ("-created",), "default_permissions": ("view", "change", "delete"),
            "permissions": (("archive_export_alertevent", "Can archive-export alert events"),),
        }),
        migrations.RunPython(remove_generated_object_add_permissions, migrations.RunPython.noop),
        migrations.RunPython(initialize_alert_timing, migrations.RunPython.noop),
    ]
