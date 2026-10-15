from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0027_readable_generated_names")]
    operations = [
        migrations.AddField(model_name="alertsettings", name="vault_findings_per_page", field=models.PositiveIntegerField(default=50)),
        migrations.AddField(model_name="alertsettings", name="vault_expiration_limit", field=models.PositiveIntegerField(default=50)),
        migrations.AddField(model_name="alertsettings", name="vault_show_expiration", field=models.BooleanField(default=True)),
        migrations.AddField(model_name="alertsettings", name="vault_show_assignments", field=models.BooleanField(default=True)),
        migrations.AddField(model_name="alertsettings", name="vault_show_evidence", field=models.BooleanField(default=True)),
    ]
