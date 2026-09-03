from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_certificates", "0016_cleanup_pre_v1_permissions"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="service",
            options={
                "default_related_name": "%(app_label)s_%(model_name)s_set",
                "ordering": ("name",),
                "permissions": (
                    ("archive_export_service", "Can archive-export services"),
                ),
            },
        ),
    ]
