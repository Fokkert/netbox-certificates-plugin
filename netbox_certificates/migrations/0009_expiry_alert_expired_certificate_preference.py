from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0008_expiry_alert_webhook_tls_verification")]
    operations = [
        migrations.AddField(
            model_name="expiryalertconfiguration",
            name="alert_on_expired_certificates",
            field=models.BooleanField(default=True, help_text="When enabled, certificates that are already expired remain eligible for an alert if their configured trigger is due and has not already been delivered.", verbose_name="Alert on already expired certificates"),
        ),
    ]
