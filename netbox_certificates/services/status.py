from django.utils import timezone
from netbox_certificates.choices import CertificateStatusChoices


def calculate_certificate_status(valid_from, valid_to, *, now=None):
    if valid_from is None or valid_to is None:
        return CertificateStatusChoices.INVALID
    now = now or timezone.now()
    if valid_to < now:
        return CertificateStatusChoices.EXPIRED
    if valid_from > now:
        return CertificateStatusChoices.NOT_YET_VALID
    return CertificateStatusChoices.ACTIVE


def refresh_certificate_statuses(queryset=None):
    from netbox_certificates.models import Certificate

    queryset = queryset if queryset is not None else Certificate.objects.all()
    now = timezone.now()
    changed = []
    for cert in queryset.only("pk", "status", "valid_from", "valid_to"):
        wanted = calculate_certificate_status(cert.valid_from, cert.valid_to, now=now)
        if cert.status != wanted:
            cert.status = wanted
            changed.append(cert)
    if changed:
        Certificate.objects.bulk_update(changed, ("status",), batch_size=500)
    return len(changed)
