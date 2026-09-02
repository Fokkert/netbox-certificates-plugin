from netbox_certificates.models import Certificate


def infer_supersedes(certificate):
    if certificate.pk is None or certificate.supersedes_id or not certificate.valid_to:
        return certificate.supersedes
    qs = Certificate.objects.exclude(pk=certificate.pk).filter(is_ca=certificate.is_ca, valid_to__lt=certificate.valid_to)
    sans = sorted(certificate.subject_alternative_names or [])
    candidates = []
    for candidate in qs.order_by("-valid_to"):
        if sans:
            if sorted(candidate.subject_alternative_names or []) == sans:
                candidates.append(candidate)
        elif candidate.subject == certificate.subject:
            candidates.append(candidate)
    if candidates:
        certificate.supersedes = candidates[0]
        certificate.save(update_fields=("supersedes",))
    return certificate.supersedes
