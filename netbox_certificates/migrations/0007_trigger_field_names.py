from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0006_expiry_alerts")]
    operations = [
        migrations.RemoveConstraint(model_name="expiryalertevent", name="netbox_certificates_unique_expiry_alert_event"),
        migrations.RenameField(model_name="certificate", old_name="alert_trigger", new_name="trigger_unit"),
        migrations.RenameField(model_name="certificate", old_name="trigger_value", new_name="alert_trigger"),
        migrations.AlterField(model_name="certificate", name="trigger_unit", field=models.CharField(blank=True, choices=[("year", "Year"), ("month", "Month"), ("week", "Week"), ("day", "Day"), ("hour", "Hour"), ("minute", "Minute"), ("second", "Second")], max_length=16, verbose_name="Trigger Unit")),
        migrations.AlterField(model_name="certificate", name="alert_trigger", field=models.PositiveIntegerField(blank=True, null=True, verbose_name="Alert Trigger")),
        migrations.RenameField(model_name="expiryalertevent", old_name="trigger_value", new_name="alert_trigger"),
        migrations.AddConstraint(model_name="expiryalertevent", constraint=models.UniqueConstraint(fields=("certificate", "method", "certificate_valid_to", "trigger_unit", "alert_trigger"), name="netbox_certificates_unique_expiry_alert_event")),
    ]
