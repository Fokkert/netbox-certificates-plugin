from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0020_certificate_alert_defaults")]
    operations = [
        migrations.AlterModelOptions(name="csr", options={
            "ordering": ("name",), "verbose_name": "CSR", "verbose_name_plural": "CSRs",
            "permissions": (("download_csr", "Can download CSR material"),),
        }),
    ]
