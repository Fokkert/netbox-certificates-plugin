from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0007_trigger_field_names")]
    operations = [
        migrations.AddField(
            model_name="expiryalertconfiguration",
            name="webhook_ignore_tls_verification",
            field=models.BooleanField(default=False, help_text="Disable HTTPS certificate and hostname verification for webhook connections. Use only for trusted internal endpoints.", verbose_name="Ignore TLS certificate verification"),
        ),
    ]
