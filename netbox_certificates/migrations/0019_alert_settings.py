from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0018_service_tags_related_name")]
    operations = [
        migrations.AddField(model_name="alertchannel", name="smtp_verify_tls", field=models.BooleanField(default=True)),
        migrations.AddField(model_name="alertchannel", name="webhook_verify_tls", field=models.BooleanField(default=True)),
        migrations.CreateModel(
            name="AlertSettings",
            fields=[
                ("id", models.PositiveSmallIntegerField(default=1, editable=False, primary_key=True, serialize=False)),
                ("rule", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to="netbox_certificates.alertrule")),
                ("email_channel", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to="netbox_certificates.alertchannel")),
                ("webhook_channel", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="+", to="netbox_certificates.alertchannel")),
            ],
            options={"default_permissions": (), "constraints": [models.CheckConstraint(condition=models.Q(id=1), name="nbcert_alert_settings_singleton")]},
        ),
    ]
