from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('netbox_certificates', '0002_alter_bundle_options_alter_privatekey_options')]
    operations = [
        migrations.RemoveField(model_name='privatekey', name='curve'),
        migrations.AddField(model_name='bundle', name='identity_fingerprint', field=models.CharField(blank=True, db_index=True, editable=False, max_length=64, null=True, unique=True)),
        migrations.AddField(model_name='bundle', name='protection_password_hash', field=models.CharField(blank=True, default='', editable=False, max_length=128)),
        migrations.AddField(model_name='certificate', name='protection_password_hash', field=models.CharField(blank=True, default='', editable=False, max_length=128)),
        migrations.AddField(model_name='csr', name='protection_password_hash', field=models.CharField(blank=True, default='', editable=False, max_length=128)),
        migrations.AddField(model_name='privatekey', name='protection_password_hash', field=models.CharField(blank=True, default='', editable=False, max_length=128)),
        migrations.AlterField(model_name='bundle', name='archive_format', field=models.CharField(default='zip', max_length=32)),
    ]
