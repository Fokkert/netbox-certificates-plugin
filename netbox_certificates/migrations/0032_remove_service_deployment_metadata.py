from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_certificates", "0031_activity_and_retired_models"),
    ]

    operations = [
        migrations.RemoveField(model_name="service", name="deployment_metadata"),
    ]
