from django.db import migrations, models
import django.db.models.deletion


def repair_mirrored_links(apps, schema_editor):
    alias = schema_editor.connection.alias
    Legacy = apps.get_model("netbox_certificates", "ArtifactLink")
    Link = apps.get_model("netbox_certificates", "ObjectLink")
    reserved = {"key_match", "csr_match", "issuer", "bundle_member", "supersedes"}
    for old in Legacy.objects.using(alias).all().iterator(chunk_size=500):
        endpoints = {"source_type_id": old.source_type_id, "source_object_id": old.source_id,
                     "target_type_id": old.target_type_id, "target_object_id": old.target_id}
        automatic = old.origin != "manual"
        if not automatic and old.relation in reserved:
            old.active = False
            old.save(using=alias, update_fields=("active",))
            automatic = True
        Link.objects.using(alias).update_or_create(
            **endpoints, relationship=old.relation,
            defaults={"automatic": automatic, "enabled": old.active, "label": old.note[:160],
                      "description": "Automatic cryptographic relationship mirrored from the internal reconciliation engine."
                      if automatic else "Manual pre-1.0 artifact relationship mirrored into ObjectLink."},
        )
        has_manual_related = Legacy.objects.using(alias).filter(
            source_type_id=old.source_type_id, source_id=old.source_id,
            target_type_id=old.target_type_id, target_id=old.target_id, relation="related",
        ).exists()
        if old.relation != "related" and not has_manual_related:
            # Remove only the obsolete mirror produced by the broken adapter,
            # never unrelated links created by users between the same objects.
            Link.objects.using(alias).filter(
                **endpoints, relationship="related", automatic=False,
                description="Manual pre-1.0 artifact relationship mirrored into ObjectLink.",
            ).delete()


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0022_global_certificate_checks")]
    operations = [
        migrations.AddField("alertsettings", "health_scan_enabled", models.BooleanField(default=True)),
        migrations.AddField("alertsettings", "health_scan_interval_minutes", models.PositiveIntegerField(default=15)),
        migrations.AddField("alertsettings", "alert_interval_minutes", models.PositiveIntegerField(default=15)),
        migrations.AddField("alertsettings", "expiration_warning_days", models.PositiveIntegerField(default=90)),
        migrations.AddField("alertsettings", "import_chain_default", models.BooleanField(default=True)),
        migrations.AddField("alertsettings", "preserve_archive_default", models.BooleanField(default=True)),
        migrations.AddField("alertsettings", "csr_rsa_bits", models.PositiveIntegerField(default=3072)),
        migrations.AddField("alertsettings", "last_health_scan", models.DateTimeField(blank=True, null=True, editable=False)),
        migrations.AddField("alertsettings", "last_alert_evaluation", models.DateTimeField(blank=True, null=True, editable=False)),
        migrations.AlterField("certificate", "status", models.CharField(default="invalid", max_length=32, editable=False)),
        migrations.AlterField("certificate", "source_format", models.CharField(default="pem", max_length=32, editable=False)),
        migrations.AlterField("csr", "source_format", models.CharField(default="pem", max_length=32, editable=False)),
        migrations.AlterField("privatekey", "source_format", models.CharField(default="pem", max_length=32, editable=False)),
        migrations.AlterField("certificate", "parent_certificate", models.ForeignKey(
            blank=True, null=True, editable=False, on_delete=django.db.models.deletion.SET_NULL,
            related_name="issued_certificates", to="netbox_certificates.certificate")),
        migrations.AlterField("certificate", "supersedes", models.ForeignKey(
            blank=True, null=True, editable=False, on_delete=django.db.models.deletion.SET_NULL,
            related_name="superseded_by", to="netbox_certificates.certificate")),
        migrations.AlterField("bundle", "archive_format", models.CharField(default="zip", max_length=32, editable=False)),
        migrations.AlterField("bundle", "status", models.CharField(default="partial", max_length=32, editable=False)),
        migrations.AlterField("bundle", "certificate", models.ForeignKey(
            blank=True, null=True, editable=False, on_delete=django.db.models.deletion.SET_NULL,
            related_name="primary_in_bundles", to="netbox_certificates.certificate")),
        migrations.AlterField("bundle", "private_key", models.ForeignKey(
            blank=True, null=True, editable=False, on_delete=django.db.models.deletion.SET_NULL,
            related_name="bundles", to="netbox_certificates.privatekey")),
        migrations.AlterField("bundle", "csr", models.ForeignKey(
            blank=True, null=True, editable=False, on_delete=django.db.models.deletion.SET_NULL,
            related_name="bundles", to="netbox_certificates.csr")),
        migrations.AlterField("bundle", "chain_certificates", models.ManyToManyField(
            blank=True, editable=False, related_name="chain_in_bundles", to="netbox_certificates.certificate")),
        migrations.RunPython(repair_mirrored_links, migrations.RunPython.noop),
    ]
