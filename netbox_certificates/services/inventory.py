from django.db.models import Q
from netbox_certificates.models import Bundle, Certificate, CSR, PrivateKey
from netbox_certificates.permissions import action_queryset


def _item(obj, *, item_id: str, role: str):
    if isinstance(obj, Certificate):
        kind, subtitle = "certificate", obj.get_status_display()
    elif isinstance(obj, PrivateKey):
        kind, subtitle = "privatekey", obj.key_type or "Private Key"
    elif isinstance(obj, CSR):
        kind, subtitle = "csr", obj.key_type or "CSR"
    else:
        kind, subtitle = obj._meta.model_name, ""
    return {
        "id": item_id,
        "type": kind,
        "role": role,
        "label": str(obj),
        "subtitle": subtitle,
        "url": obj.get_absolute_url(),
        "groups": [{"id": g.pk, "name": g.name, "url": g.get_absolute_url()} for g in obj.groups.all().order_by("name")],
    }


def _bundle_chain(bundle, leaf, visible_certificates):
    result, seen = [], set()
    current = leaf
    while current is not None and current.parent_certificate_id and current.pk not in seen:
        seen.add(current.pk)
        parent = visible_certificates.get(current.parent_certificate_id)
        if parent is None or parent.pk in seen:
            break
        result.append(parent)
        current = parent
    existing_ids = {cert.pk for cert in result}
    if leaf is not None:
        existing_ids.add(leaf.pk)
    for cert in bundle.chain_certificates.all():
        visible = visible_certificates.get(cert.pk)
        if visible is not None and visible.pk not in existing_ids:
            result.append(visible)
            existing_ids.add(visible.pk)
    return result


def _unbundled_objects(visible_certificates, visible_keys, visible_csrs):
    bundled_certificate_ids = set(
        Certificate.objects.filter(Q(primary_in_bundles__isnull=False) | Q(chain_in_bundles__isnull=False))
        .values_list("pk", flat=True).distinct()
    )
    bundled_key_ids = set(PrivateKey.objects.filter(bundles__isnull=False).values_list("pk", flat=True).distinct())
    bundled_csr_ids = set(CSR.objects.filter(bundles__isnull=False).values_list("pk", flat=True).distinct())
    return {
        "certificates": [_item(obj, item_id=f"unbundled-certificate-{obj.pk}", role="CA Certificate" if obj.is_ca else "Certificate") for obj in visible_certificates.values() if obj.pk not in bundled_certificate_ids],
        "private_keys": [_item(obj, item_id=f"unbundled-privatekey-{obj.pk}", role="Private Key") for obj in visible_keys.values() if obj.pk not in bundled_key_ids],
        "csrs": [_item(obj, item_id=f"unbundled-csr-{obj.pk}", role="CSR") for obj in visible_csrs.values() if obj.pk not in bundled_csr_ids],
    }


def build_inventory(user):
    visible_bundles = list(action_queryset(Bundle, user, "view").select_related("certificate", "private_key", "csr").prefetch_related("chain_certificates", "groups").order_by("name", "pk"))
    visible_certificates = {obj.pk: obj for obj in action_queryset(Certificate, user, "view").select_related("parent_certificate").prefetch_related("groups").order_by("name", "pk")}
    visible_keys = {obj.pk: obj for obj in action_queryset(PrivateKey, user, "view").prefetch_related("groups").order_by("name", "pk")}
    visible_csrs = {obj.pk: obj for obj in action_queryset(CSR, user, "view").prefetch_related("groups").order_by("name", "pk")}
    groups = []
    for bundle in visible_bundles:
        group_id = f"bundle-{bundle.pk}"
        members = []
        certificate = visible_certificates.get(bundle.certificate_id) if bundle.certificate_id else None
        private_key = visible_keys.get(bundle.private_key_id) if bundle.private_key_id else None
        csr = visible_csrs.get(bundle.csr_id) if bundle.csr_id else None
        if certificate is not None:
            members.append(_item(certificate, item_id=f"{group_id}-certificate-{certificate.pk}", role="CA Certificate" if certificate.is_ca else "Certificate"))
        if private_key is not None:
            members.append(_item(private_key, item_id=f"{group_id}-privatekey-{private_key.pk}", role="Private Key"))
        if csr is not None:
            members.append(_item(csr, item_id=f"{group_id}-csr-{csr.pk}", role="CSR"))
        chain = _bundle_chain(bundle, certificate, visible_certificates)
        for index, ca_cert in enumerate(chain):
            role = "Root CA" if ca_cert.parent_certificate_id is None or (index == len(chain) - 1 and not ca_cert.parent_certificate_id) else "Intermediate CA"
            members.append(_item(ca_cert, item_id=f"{group_id}-ca-{ca_cert.pk}", role=role))
        groups.append({
            "id": group_id,
            "type": "bundle",
            "label": bundle.name,
            "subtitle": bundle.get_status_display(),
            "url": bundle.get_absolute_url(),
            "groups": [{"id": g.pk, "name": g.name, "url": g.get_absolute_url()} for g in bundle.groups.all().order_by("name")],
            "members": members,
        })
    return {
        "groups": groups,
        "unbundled": _unbundled_objects(visible_certificates, visible_keys, visible_csrs),
        "counts": {"bundles": len(visible_bundles), "certificates": len(visible_certificates), "keys": len(visible_keys), "csrs": len(visible_csrs)},
    }
