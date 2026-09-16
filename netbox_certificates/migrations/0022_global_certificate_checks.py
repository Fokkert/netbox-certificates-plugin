from django.db import migrations, models


def migrate_settings(apps, schema_editor):
    alias = schema_editor.connection.alias
    Settings = apps.get_model("netbox_certificates", "AlertSettings")
    Policy = apps.get_model("netbox_certificates", "CertificatePolicy")
    Rule = apps.get_model("netbox_certificates", "AlertRule")
    config, _ = Settings.objects.using(alias).get_or_create(pk=1)
    policies = Policy.objects.using(alias).filter(enabled=True)
    # A single definition can be carried over unambiguously. Multiple differing
    # definitions remain stored for audit; documented global defaults apply.
    if policies.count() == 1:
        policy = policies.first()
        for field in ("minimum_rsa_bits", "max_validity_days", "require_san", "allow_wildcards", "forbid_key_reuse"):
            setattr(config, field, getattr(policy, field))
        if config.minimum_rsa_bits not in (2048, 3072, 4096, 8192):
            config.minimum_rsa_bits = 2048
        if config.max_validity_days is not None and not 1 <= config.max_validity_days <= 365000:
            config.max_validity_days = None
        config.save(using=alias)
    for rule in Rule.objects.using(alias).all():
        changed = []
        if "policy" in rule.categories:
            rule.categories = list(dict.fromkeys("configuration" if value == "policy" else value for value in rule.categories))
            changed.append("categories")
        old_codes = {"CERTIFICATE_POLICY_VIOLATION", "CSR_POLICY_VIOLATION", "BUNDLE_POLICY_VIOLATION"}
        if old_codes.intersection(rule.finding_codes):
            rule.finding_codes = list(dict.fromkeys("CERTIFICATE_SETTINGS_VIOLATION" if code in old_codes else code for code in rule.finding_codes))
            changed.append("finding_codes")
        if changed:
            rule.save(using=alias, update_fields=changed)
    apps.get_model("auth", "Permission").objects.using(alias).filter(
        content_type__app_label="netbox_certificates", content_type__model="certificatepolicy",
    ).delete()


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0021_csr_plural_label")]
    operations = [
        migrations.AddField("alertsettings", "minimum_rsa_bits", models.PositiveIntegerField(default=2048)),
        migrations.AddField("alertsettings", "max_validity_days", models.PositiveIntegerField(blank=True, null=True)),
        migrations.AddField("alertsettings", "require_san", models.BooleanField(default=True)),
        migrations.AddField("alertsettings", "allow_wildcards", models.BooleanField(default=True)),
        migrations.AddField("alertsettings", "forbid_key_reuse", models.BooleanField(default=False)),
        migrations.AlterModelOptions("certificatepolicy", {"ordering": ("name",), "default_permissions": (), "permissions": ()}),
        migrations.AlterModelOptions("privatekey", {"ordering": ("name",), "verbose_name": "private key", "verbose_name_plural": "private keys", "permissions": (
            ("download_privatekey", "Can download private key material"), ("use_privatekey", "Can use private key to sign CSRs"),
        )}),
        migrations.RunPython(migrate_settings, migrations.RunPython.noop),
    ]
