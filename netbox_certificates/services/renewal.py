"""Derive renewal relationships from certificate identity and validity."""
from collections import defaultdict
from itertools import groupby

from netbox_certificates.models import Certificate


def renewal_identity(certificate):
    sans = tuple(sorted(certificate.subject_alternative_names or []))
    return certificate.is_ca, ("sans", sans) if sans else ("subject", certificate.subject)


def reconcile_supersedes():
    groups = defaultdict(list)
    for certificate in Certificate.objects.all().iterator(chunk_size=200):
        if certificate.valid_to:
            groups[renewal_identity(certificate)].append(certificate)
        elif certificate.supersedes_id:
            certificate.supersedes = None
            certificate.save(update_fields=("supersedes",))
    for certificates in groups.values():
        certificates.sort(key=lambda obj: (obj.valid_to, obj.pk))
        previous = None
        for _, peers in groupby(certificates, key=lambda obj: obj.valid_to):
            peers = list(peers)
            for certificate in peers:
                expected = previous.pk if previous else None
                if certificate.supersedes_id != expected:
                    certificate.supersedes = previous
                    certificate.save(update_fields=("supersedes",))
            previous = peers[-1]


def infer_supersedes(certificate):
    if certificate.pk is None:
        return None
    reconcile_supersedes()
    certificate.refresh_from_db(fields=("supersedes",))
    return certificate.supersedes
