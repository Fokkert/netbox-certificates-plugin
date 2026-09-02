from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from cryptography import x509

from netbox_certificates.choices import BundleFormatChoices, BundleStatusChoices, LinkOriginChoices, LinkRelationChoices
from netbox_certificates.models import ArtifactLink, Bundle, Certificate, CSR, PrivateKey


def _ct(obj):
    return ContentType.objects.get_for_model(obj, for_concrete_model=False)


def create_link(source, target, relation, origin=LinkOriginChoices.AUTOMATIC, note="", reactivate=False, update_origin=False):
    if source.pk is None or target.pk is None:
        return None
    link, _ = ArtifactLink.objects.get_or_create(
        source_type=_ct(source), source_id=source.pk,
        target_type=_ct(target), target_id=target.pk,
        relation=relation,
        defaults={"origin": origin, "note": note, "active": True},
    )
    changed = []
    if reactivate and not link.active:
        link.active = True
        changed.append("active")
    if update_origin and link.origin != origin:
        link.origin = origin
        changed.append("origin")
    if note and link.note != note:
        link.note = note
        changed.append("note")
    if changed:
        link.save(update_fields=tuple(changed))
    return link


def link_matching_artifacts(obj, origin=LinkOriginChoices.AUTOMATIC):
    fp = getattr(obj, "public_key_fingerprint", None)
    if not fp:
        return
    if isinstance(obj, Certificate):
        for key in PrivateKey.objects.filter(public_key_fingerprint=fp):
            create_link(obj, key, LinkRelationChoices.KEY_MATCH, origin=origin, update_origin=True)
        for csr in CSR.objects.filter(public_key_fingerprint=fp):
            create_link(obj, csr, LinkRelationChoices.CSR_MATCH, origin=origin, update_origin=True)
    elif isinstance(obj, PrivateKey):
        for cert in Certificate.objects.filter(public_key_fingerprint=fp):
            create_link(cert, obj, LinkRelationChoices.KEY_MATCH, origin=origin, update_origin=True)
        for csr in CSR.objects.filter(public_key_fingerprint=fp):
            create_link(csr, obj, LinkRelationChoices.KEY_MATCH, origin=origin, update_origin=True)
    elif isinstance(obj, CSR):
        for cert in Certificate.objects.filter(public_key_fingerprint=fp):
            create_link(cert, obj, LinkRelationChoices.CSR_MATCH, origin=origin, update_origin=True)
        for key in PrivateKey.objects.filter(public_key_fingerprint=fp):
            create_link(obj, key, LinkRelationChoices.KEY_MATCH, origin=origin, update_origin=True)


def resolve_certificate_parent(certificate: Certificate):
    try:
        child = x509.load_pem_x509_certificate(certificate.material.encode())
    except Exception:
        return None
    if child.subject == child.issuer:
        try:
            child.verify_directly_issued_by(child)
        except Exception:
            return None
        if certificate.parent_certificate_id:
            certificate.parent_certificate = None
            certificate.save(update_fields=("parent_certificate",))
        return None
    for candidate in Certificate.objects.exclude(pk=certificate.pk):
        try:
            issuer = x509.load_pem_x509_certificate(candidate.material.encode())
            child.verify_directly_issued_by(issuer)
        except Exception:
            continue
        if certificate.parent_certificate_id != candidate.pk:
            certificate.parent_certificate = candidate
            certificate.save(update_fields=("parent_certificate",))
        create_link(certificate, candidate, LinkRelationChoices.ISSUER)
        return candidate
    return None


def _bundle_members_for_fingerprint(fingerprint):
    certificate = Certificate.objects.filter(public_key_fingerprint=fingerprint).order_by("-pk").first()
    private_key = PrivateKey.objects.filter(public_key_fingerprint=fingerprint).order_by("-pk").first()
    csr = CSR.objects.filter(public_key_fingerprint=fingerprint).order_by("-pk").first()
    return certificate, private_key, csr


def _automatic_bundle_name(certificate=None, private_key=None, csr=None):
    if certificate is not None:
        return f"{certificate.name} Bundle"
    if csr is not None:
        return f"{csr.name} Bundle"
    if private_key is not None:
        return f"{private_key.name} Bundle"
    return "Automatic Bundle"


def sync_bundle_links(bundle: Bundle, origin=LinkOriginChoices.AUTOMATIC):
    # Primary members and chain certificates all get explicit Bundle links. Chain
    # certificates remain chain members in the Bundle model; this link simply makes
    # navigation reciprocal (CA -> Bundle and Bundle -> CA).
    selected = [obj for obj in (bundle.certificate, bundle.private_key, bundle.csr) if obj is not None]
    selected.extend(c for c in bundle.chain_certificates.all() if c not in selected)
    source_ct = _ct(bundle)
    selected_keys = {(_ct(obj).pk, obj.pk) for obj in selected}
    existing = ArtifactLink.objects.filter(
        source_type=source_ct,
        source_id=bundle.pk,
        relation=LinkRelationChoices.BUNDLE_MEMBER,
    )
    for link in existing:
        key = (link.target_type_id, link.target_id)
        if key not in selected_keys:
            if link.active:
                link.active = False
                link.save(update_fields=("active",))
            continue
        updates = []
        if not link.active:
            link.active = True
            updates.append("active")
        if link.origin != origin:
            link.origin = origin
            updates.append("origin")
        if updates:
            link.save(update_fields=tuple(updates))
    for target in selected:
        create_link(
            bundle, target, LinkRelationChoices.BUNDLE_MEMBER,
            origin=origin, reactivate=True, update_origin=True,
            note="Certificate chain member" if isinstance(target, Certificate) and target.pk != bundle.certificate_id else "",
        )
    primary_count = sum(obj is not None for obj in (bundle.certificate, bundle.private_key, bundle.csr))
    wanted_status = BundleStatusChoices.COMPLETE if primary_count == 3 else BundleStatusChoices.PARTIAL
    if bundle.status != wanted_status:
        bundle.status = wanted_status
        bundle.save(update_fields=("status",))


def ensure_automatic_bundle(obj, origin=LinkOriginChoices.AUTOMATIC):
    fingerprint = getattr(obj, "public_key_fingerprint", None)
    if not fingerprint:
        return None
    certificate, private_key, csr = _bundle_members_for_fingerprint(fingerprint)
    members = [member for member in (certificate, private_key, csr) if member is not None]
    # Any two matching primary artifact types form a valid Bundle.
    if len(members) < 2:
        return None
    bundle = Bundle.objects.filter(identity_fingerprint=fingerprint).first()
    if bundle is None:
        candidates = Bundle.objects.filter(identity_fingerprint__isnull=True)
        for member in members:
            if isinstance(member, Certificate):
                candidate = candidates.filter(certificate=member).first()
            elif isinstance(member, PrivateKey):
                candidate = candidates.filter(private_key=member).first()
            else:
                candidate = candidates.filter(csr=member).first()
            if candidate is not None:
                bundle = candidate
                break
    name = _automatic_bundle_name(certificate=certificate, private_key=private_key, csr=csr)
    if bundle is None:
        bundle = Bundle.objects.create(
            name=name,
            identity_fingerprint=fingerprint,
            archive_format=BundleFormatChoices.ZIP,
            certificate=certificate,
            private_key=private_key,
            csr=csr,
            status=BundleStatusChoices.COMPLETE if len(members) == 3 else BundleStatusChoices.PARTIAL,
        )
    else:
        changed = []
        for field, value in (
            ("identity_fingerprint", fingerprint),
            ("name", name),
            ("certificate", certificate),
            ("private_key", private_key),
            ("csr", csr),
        ):
            current = getattr(bundle, f"{field}_id", None) if field in {"certificate", "private_key", "csr"} else getattr(bundle, field)
            wanted = value.pk if field in {"certificate", "private_key", "csr"} and value else value
            if current != wanted:
                setattr(bundle, field, value)
                changed.append(field)
        if bundle.archive_format == BundleFormatChoices.MANUAL:
            bundle.archive_format = BundleFormatChoices.ZIP
            changed.append("archive_format")
        if changed:
            bundle.save(update_fields=tuple(changed))
    # Preserve grouping context: an automatically-created Bundle inherits the union
    # of groups already assigned to its matching primary artifacts.
    inherited_group_ids = set()
    for member in members:
        inherited_group_ids.update(member.groups.values_list("pk", flat=True))
    if inherited_group_ids:
        bundle.groups.add(*inherited_group_ids)
    sync_bundle_links(bundle, origin=origin)
    return bundle


def reconcile_links():
    with transaction.atomic():
        artifacts = []
        for obj in Certificate.objects.all():
            link_matching_artifacts(obj)
            resolve_certificate_parent(obj)
            artifacts.append(obj)
        for obj in CSR.objects.all():
            link_matching_artifacts(obj)
            artifacts.append(obj)
        for obj in PrivateKey.objects.all():
            link_matching_artifacts(obj)
            artifacts.append(obj)
        processed = set()
        for obj in artifacts:
            fp = getattr(obj, "public_key_fingerprint", None)
            if fp and fp not in processed:
                ensure_automatic_bundle(obj)
                processed.add(fp)
        for bundle in Bundle.objects.prefetch_related("chain_certificates"):
            sync_bundle_links(bundle)
        from .certificate_authorities import sync_all_certificate_authorities
        sync_all_certificate_authorities()
