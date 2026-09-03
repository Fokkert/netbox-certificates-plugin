from django.db import migrations


LEGACY_PUBLIC_MODELS = (
    "artifactlink",
    "certificateauthority",
    "expiryalertconfiguration",
    "expiryalertevent",
)


def remove_pre_v1_permissions(apps, schema_editor):
    Permission = apps.get_model("auth", "Permission")
    Permission.objects.filter(
        content_type__app_label="netbox_certificates",
        content_type__model__in=LEGACY_PUBLIC_MODELS,
    ).delete()


def reverse_noop(apps, schema_editor):
    # Django's post_migrate permission creation can recreate model permissions
    # when returning to an older package. 1.0 does not synthesize legacy
    # permission rows during a reverse migration.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_certificates", "0015_migrate_legacy_links"),
    ]

    operations = [
        migrations.RunPython(remove_pre_v1_permissions, reverse_noop),
    ]
