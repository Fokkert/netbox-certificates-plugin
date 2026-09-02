from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0004_remove_bundle_protection_password_hash_and_more")]
    operations = [
        migrations.AddField(model_name="certificate", name="supersedes", field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name="superseded_by", to="netbox_certificates.certificate")),
        migrations.AlterModelOptions(name="certificate", options={"ordering": ("name", "valid_to"), "permissions": (("download_certificate", "Can download certificate material"),), "verbose_name": "certificate", "verbose_name_plural": "certificates"}),
        migrations.AlterModelOptions(name="privatekey", options={"ordering": ("name",), "permissions": (("download_privatekey", "Can download private key material"),), "verbose_name": "private key", "verbose_name_plural": "private keys"}),
        migrations.AlterModelOptions(name="csr", options={"ordering": ("name",), "permissions": (("download_csr", "Can download CSR material"),), "verbose_name": "CSR", "verbose_name_plural": "CSRs"}),
        migrations.AlterModelOptions(name="bundle", options={"ordering": ("name",), "permissions": (("export_bundle", "Can export bundle material"), ("export_pfx_bundle", "Can export bundle as PKCS#12/PFX")), "verbose_name": "bundle", "verbose_name_plural": "bundles"}),
    ]
