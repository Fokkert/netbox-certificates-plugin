from __future__ import annotations

import re

from cryptography import x509

from netbox_certificates.models import Certificate, CertificateAuthority


def authority_name_from_issuer(issuer_dn: str) -> str:
    """Return a compact human-readable CA identity name from a distinguished name."""
    issuer_dn = (issuer_dn or "").strip()
    if not issuer_dn:
        return "Unknown Certificate Authority"
    for key in ("CN", "O", "OU"):
        match = re.search(rf"(?:^|,){key}=((?:\\.|[^,])*)", issuer_dn)
        if match and match.group(1):
            value = re.sub(r"\\(.)", r"\1", match.group(1)).strip()
            if value:
                return value
    return issuer_dn


def _is_self_signed_root(certificate: Certificate) -> bool:
    """Return True only for a cryptographically self-signed CA certificate."""
    if certificate is None or not certificate.is_ca:
        return False
    try:
        parsed = x509.load_pem_x509_certificate(certificate.material.encode("ascii"))
        if parsed.subject != parsed.issuer:
            return False
        parsed.verify_directly_issued_by(parsed)
        return True
    except Exception:
        return False


def root_certificate_for(certificate: Certificate, max_depth: int = 32) -> Certificate | None:
    """Walk the stored issuer chain and return its self-signed root CA, if available."""
    if certificate is None or certificate.pk is None:
        return None
    current = certificate
    seen = set()
    for _ in range(max_depth):
        if current.pk in seen:
            return None
        seen.add(current.pk)
        if _is_self_signed_root(current):
            return current
        if current.parent_certificate_id is None:
            return None
        current = current.parent_certificate
    return None


def sync_certificate_authority(certificate: Certificate) -> CertificateAuthority | None:
    """Attach a certificate to its root CA identity only when the root is stored."""
    root = root_certificate_for(certificate)
    if root is None:
        if certificate.authority_id is not None:
            Certificate.objects.filter(pk=certificate.pk).update(authority=None)
            certificate.authority = None
        return None

    root_dn = (root.subject or root.issuer or "").strip()
    if not root_dn:
        return None

    name = authority_name_from_issuer(root_dn)
    authority, created = CertificateAuthority.objects.get_or_create(
        issuer_dn=root_dn,
        defaults={"name": name},
    )
    if not created and authority.name != name:
        authority.name = name
        authority.save(update_fields=("name", "last_updated"))

    if certificate.authority_id != authority.pk:
        Certificate.objects.filter(pk=certificate.pk).update(authority=authority)
        certificate.authority = authority
    return authority


def sync_all_certificate_authorities(*, remove_stale: bool = True) -> None:
    """Recompute root-CA identities for every stored certificate."""
    used = set()
    queryset = Certificate.objects.select_related(
        "parent_certificate__parent_certificate__parent_certificate"
    ).order_by("pk")
    for certificate in queryset:
        authority = sync_certificate_authority(certificate)
        if authority is not None:
            used.add(authority.pk)
    if remove_stale:
        CertificateAuthority.objects.exclude(pk__in=used).delete()
