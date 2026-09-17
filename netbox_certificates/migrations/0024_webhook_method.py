from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0023_preferences_and_derived_fields")]
    operations = [migrations.AddField(
        model_name="alertchannel", name="webhook_method",
        field=models.CharField(max_length=7, default="POST", choices=[
            (method, method) for method in ("POST", "GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")
        ]),
    )]
