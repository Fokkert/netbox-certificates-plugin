from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [('netbox_certificates', '0001_initial')]
    operations = [
        migrations.AlterModelOptions(name='bundle', options={'ordering': ('name',), 'permissions': ()}),
        migrations.AlterModelOptions(name='privatekey', options={'ordering': ('name',), 'permissions': ()}),
    ]
