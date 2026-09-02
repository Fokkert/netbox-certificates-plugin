from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [('netbox_certificates', '0003_remove_privatekey_curve_bundle_identity_fingerprint_and_more')]
    operations = [
        migrations.RemoveField(model_name='bundle', name='protection_password_hash'),
        migrations.RemoveField(model_name='certificate', name='protection_password_hash'),
        migrations.RemoveField(model_name='csr', name='protection_password_hash'),
        migrations.RemoveField(model_name='privatekey', name='protection_password_hash'),
    ]
