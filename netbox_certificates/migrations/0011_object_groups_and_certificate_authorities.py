import re

import django.db.models.deletion
import netbox.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


def _identity_name(issuer_dn):
    for key in ("CN", "O", "OU"):
        match = re.search(rf"(?:^|,){key}=((?:\\.|[^,])*)", issuer_dn)
        if match and match.group(1):
            value = match.group(1)
            value = re.sub(r"\\(.)", r"\1", value).strip()
            if value:
                return value
    return issuer_dn


def backfill_certificate_authorities(apps, schema_editor):
    Certificate = apps.get_model("netbox_certificates", "Certificate")
    CertificateAuthority = apps.get_model("netbox_certificates", "CertificateAuthority")
    for certificate in Certificate.objects.exclude(issuer="").iterator():
        issuer_dn = (certificate.issuer or "").strip()
        if not issuer_dn:
            continue
        authority, _ = CertificateAuthority.objects.get_or_create(
            issuer_dn=issuer_dn,
            defaults={"name": _identity_name(issuer_dn)},
        )
        Certificate.objects.filter(pk=certificate.pk).update(authority_id=authority.pk)


def clear_certificate_authorities(apps, schema_editor):
    Certificate = apps.get_model("netbox_certificates", "Certificate")
    Certificate.objects.update(authority_id=None)


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_certificates", "0010_groups_and_repeat_alerts"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="artifactgroup",
            options={
                "ordering": ("name",),
                "verbose_name": "object group",
                "verbose_name_plural": "object groups",
            },
        ),
        migrations.AddField(
            model_name="artifactgroup",
            name="child_groups",
            field=models.ManyToManyField(
                blank=True,
                related_name="parent_groups",
                symmetrical=False,
                to="netbox_certificates.artifactgroup",
                verbose_name="contained object groups",
            ),
        ),
        migrations.CreateModel(
            name="CertificateAuthority",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ("description", models.CharField(blank=True, max_length=200)),
                ("comments", models.TextField(blank=True)),
                ("name", models.CharField(db_index=True, max_length=255)),
                ("issuer_dn", models.TextField(editable=False, unique=True)),
                ("owner", models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.PROTECT, to="users.owner")),
                ("tags", taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag")),
            ],
            options={
                "verbose_name": "certificate authority",
                "verbose_name_plural": "certificate authorities",
                "ordering": ("name", "pk"),
            },
            bases=(netbox.models.deletion.DeleteMixin, models.Model),
        ),
        migrations.AddField(
            model_name="certificate",
            name="authority",
            field=models.ForeignKey(
                blank=True,
                editable=False,
                null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name="certificates",
                to="netbox_certificates.certificateauthority",
            ),
        ),
        migrations.RunPython(backfill_certificate_authorities, clear_certificate_authorities),
    ]
