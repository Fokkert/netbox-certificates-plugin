import django.db.models.deletion
from django.db import migrations, models


def convert_group_membership_to_tree(apps, schema_editor):
    ArtifactGroup = apps.get_model("netbox_certificates", "ArtifactGroup")

    # 0.4.2 allowed a Group to have multiple parent Groups through child_groups.
    # 0.4.3 is deliberately a folder/tree model: one parent, many children.
    # If legacy data has multiple parents, the first parent by PK wins deterministically.
    for parent in ArtifactGroup.objects.order_by("pk").iterator():
        for child in parent.child_groups.order_by("pk").iterator():
            if child.pk == parent.pk or child.parent_id is not None:
                continue
            ArtifactGroup.objects.filter(pk=child.pk).update(parent_id=parent.pk)


def restore_group_membership_m2m(apps, schema_editor):
    ArtifactGroup = apps.get_model("netbox_certificates", "ArtifactGroup")
    for child in ArtifactGroup.objects.exclude(parent_id=None).iterator():
        parent = ArtifactGroup.objects.filter(pk=child.parent_id).first()
        if parent is not None:
            parent.child_groups.add(child)


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_certificates", "0011_object_groups_and_certificate_authorities"),
    ]

    operations = [
        migrations.AddField(
            model_name="artifactgroup",
            name="parent",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="children",
                to="netbox_certificates.artifactgroup",
                verbose_name="parent group",
            ),
        ),
        migrations.RunPython(convert_group_membership_to_tree, restore_group_membership_m2m),
        migrations.RemoveField(
            model_name="artifactgroup",
            name="child_groups",
        ),
        migrations.AlterModelOptions(
            name="artifactgroup",
            options={
                "ordering": ("name",),
                "verbose_name": "group",
                "verbose_name_plural": "groups",
            },
        ),
        migrations.AlterField(
            model_name="expiryalertconfiguration",
            name="smtp_host",
            field=models.CharField(blank=True, max_length=255, verbose_name="SMTP host"),
        ),
        migrations.AlterField(
            model_name="expiryalertconfiguration",
            name="smtp_port",
            field=models.PositiveIntegerField(default=587, verbose_name="SMTP port"),
        ),
        migrations.AlterField(
            model_name="expiryalertconfiguration",
            name="smtp_username",
            field=models.CharField(blank=True, max_length=255, verbose_name="SMTP username"),
        ),
        migrations.AlterField(
            model_name="expiryalertconfiguration",
            name="smtp_use_tls",
            field=models.BooleanField(default=True, verbose_name="Use STARTTLS"),
        ),
        migrations.AlterField(
            model_name="expiryalertconfiguration",
            name="smtp_use_ssl",
            field=models.BooleanField(default=False, verbose_name="Use implicit SSL/TLS"),
        ),
        migrations.AlterField(
            model_name="expiryalertconfiguration",
            name="email_from_address",
            field=models.EmailField(blank=True, max_length=254, verbose_name="From address"),
        ),
        migrations.AlterField(
            model_name="expiryalertconfiguration",
            name="email_recipients",
            field=models.TextField(blank=True, verbose_name="Recipients"),
        ),
        migrations.AlterField(
            model_name="expiryalertconfiguration",
            name="include_superusers",
            field=models.BooleanField(default=True, verbose_name="Include active NetBox superusers"),
        ),
        migrations.AlterField(
            model_name="expiryalertconfiguration",
            name="webhook_enabled",
            field=models.BooleanField(default=False, verbose_name="Enable webhook"),
        ),
        migrations.AlterField(
            model_name="expiryalertconfiguration",
            name="webhook_allow_http",
            field=models.BooleanField(default=False, verbose_name="Allow insecure HTTP webhook"),
        ),
    ]
