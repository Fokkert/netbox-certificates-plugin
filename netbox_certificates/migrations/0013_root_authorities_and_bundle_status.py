import re

from django.db import migrations


def _identity_name(dn):
    for key in ("CN", "O", "OU"):
        match = re.search(rf"(?:^|,){key}=((?:\\.|[^,])*)", dn)
        if match and match.group(1):
            value = re.sub(r"\\(.)", r"\1", match.group(1)).strip()
            if value:
                return value
    return dn


def _root_for(certificate, Certificate, max_depth=32):
    current = certificate
    seen = set()
    for _ in range(max_depth):
        if current.pk in seen:
            return None
        seen.add(current.pk)
        subject = (current.subject or "").strip()
        issuer = (current.issuer or "").strip()
        if current.is_ca and subject and subject == issuer:
            return current
        if current.parent_certificate_id is None:
            return None
        current = Certificate.objects.filter(pk=current.parent_certificate_id).first()
        if current is None:
            return None
    return None


def root_only_authorities_and_bundle_status(apps, schema_editor):
    Certificate = apps.get_model("netbox_certificates", "Certificate")
    CertificateAuthority = apps.get_model("netbox_certificates", "CertificateAuthority")
    Bundle = apps.get_model("netbox_certificates", "Bundle")

    used_authority_ids = set()
    for certificate in Certificate.objects.order_by("pk").iterator():
        root = _root_for(certificate, Certificate)
        if root is None:
            Certificate.objects.filter(pk=certificate.pk).update(authority_id=None)
            continue

        root_dn = (root.subject or root.issuer or "").strip()
        if not root_dn:
            Certificate.objects.filter(pk=certificate.pk).update(authority_id=None)
            continue

        # 0.4.2/0.4.3 already created an identity for the root DN because a
        # self-signed root has issuer == subject. Reuse it to preserve any
        # owner/description/tags attached to the identity.
        authority = CertificateAuthority.objects.filter(issuer_dn=root_dn).first()
        if authority is None:
            authority = CertificateAuthority.objects.create(
                name=_identity_name(root_dn),
                issuer_dn=root_dn,
            )
        Certificate.objects.filter(pk=certificate.pk).update(authority_id=authority.pk)
        used_authority_ids.add(authority.pk)

    # Intermediate issuer identities are no longer Certificate Authorities.
    CertificateAuthority.objects.exclude(pk__in=used_authority_ids).delete()

    # A Bundle is Complete only when all three primary objects exist.
    for bundle in Bundle.objects.all().iterator():
        complete = all((bundle.certificate_id, bundle.private_key_id, bundle.csr_id))
        wanted = "complete" if complete else "partial"
        if bundle.status != wanted:
            Bundle.objects.filter(pk=bundle.pk).update(status=wanted)


def noop_reverse(apps, schema_editor):
    # Root-only CA identities and corrected Bundle status are intentional data
    # normalization. Recreating intermediate identities on rollback would be
    # misleading, so the reverse migration leaves data in the normalized state.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_certificates", "0012_group_hierarchy_and_ui_labels"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="expiryalertconfiguration",
            options={
                "default_permissions": ("add", "change", "view"),
                "permissions": (("test_expiryalertconfiguration", "Can test expiration alert configuration"),),
                "verbose_name": "expiration alert configuration",
                "verbose_name_plural": "expiration alert configuration",
            },
        ),
        migrations.AlterModelOptions(
            name="expiryalertevent",
            options={
                "default_permissions": ("view", "delete"),
                "ordering": ("-last_attempt_at", "-created"),
                "verbose_name": "expiration alert event",
                "verbose_name_plural": "expiration alert events",
            },
        ),
        migrations.RunPython(root_only_authorities_and_bundle_status, noop_reverse),
    ]
