import django.db.models.deletion
import netbox.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("extras", "0134_owner"),
        ("users", "0015_owner"),
        ("netbox_certificates", "0009_expiry_alert_expired_certificate_preference"),
    ]

    operations = [
        migrations.CreateModel(
            name="ArtifactGroup",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ("description", models.CharField(blank=True, max_length=200)),
                ("comments", models.TextField(blank=True)),
                ("name", models.CharField(max_length=200, unique=True)),
                ("owner", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to="users.owner")),
                ("tags", taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag")),
            ],
            options={
                "verbose_name": "certificate group",
                "verbose_name_plural": "certificate groups",
                "ordering": ("name",),
            },
            bases=(netbox.models.deletion.DeleteMixin, models.Model),
        ),
        migrations.AddField(
            model_name="certificate",
            name="groups",
            field=models.ManyToManyField(blank=True, related_name="certificates", to="netbox_certificates.artifactgroup"),
        ),
        migrations.AddField(
            model_name="privatekey",
            name="groups",
            field=models.ManyToManyField(blank=True, related_name="private_keys", to="netbox_certificates.artifactgroup"),
        ),
        migrations.AddField(
            model_name="csr",
            name="groups",
            field=models.ManyToManyField(blank=True, related_name="csrs", to="netbox_certificates.artifactgroup"),
        ),
        migrations.AddField(
            model_name="bundle",
            name="groups",
            field=models.ManyToManyField(blank=True, related_name="bundles", to="netbox_certificates.artifactgroup"),
        ),
        migrations.AddField(
            model_name="expiryalertconfiguration",
            name="alert_repeat_mode",
            field=models.CharField(
                choices=[("once", "Send once per trigger"), ("while_due", "Send every check while due")],
                default="once",
                help_text="Send once per certificate validity/trigger/method, or repeat on every configured check while the certificate remains due.",
                max_length=16,
                verbose_name="Alert repeat behavior",
            ),
        ),
    ]
