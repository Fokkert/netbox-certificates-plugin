from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0028_vault_preferences")]
    operations = [
        migrations.AddField(
            model_name="service", name="certificate_check_enabled",
            field=models.BooleanField(default=False, verbose_name="Check live certificate"),
        ),
        migrations.AddField(
            model_name="alertsettings", name="service_checks_enabled",
            field=models.BooleanField(default=False),
        ),
    ]
