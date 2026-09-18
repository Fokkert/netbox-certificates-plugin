"""Align the serialized default callable; existing rule statuses are unchanged."""
import netbox_certificates.models_v1
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0024_webhook_method")]

    operations = [
        migrations.AlterField(
            model_name="alertrule",
            name="statuses",
            field=models.JSONField(
                blank=True,
                default=netbox_certificates.models_v1.default_alert_statuses,
            ),
        ),
    ]
