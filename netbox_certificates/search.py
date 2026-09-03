from netbox.search import SearchIndex, register_search

from .models import ArtifactGroup, Bundle, Certificate, CSR, PrivateKey
from .models_v1 import AlertChannel, AlertEvent, AlertRule, CertificatePolicy, HealthFinding, ObjectLink, Service


def _existing(model, candidates):
    fields = []
    for name, weight in candidates:
        try:
            field = model._meta.get_field(name)
        except Exception:
            continue
        if getattr(field, "concrete", False) and not getattr(field, "many_to_many", False):
            fields.append((name, weight))
    return tuple(fields)


@register_search
class ArtifactGroupIndex(SearchIndex):
    model = ArtifactGroup
    fields = _existing(ArtifactGroup, (("name", 100), ("description", 500), ("comments", 5000)))


@register_search
class ServiceIndex(SearchIndex):
    model = Service
    fields = _existing(
        Service,
        (
            ("name", 100),
            ("deployment", 150),
            ("other_type", 180),
            ("protocol", 180),
            ("primary_url", 200),
            ("hostname", 200),
            ("sni_name", 200),
            ("external_reference", 300),
            ("contact", 500),
            ("description", 500),
            ("comments", 5000),
        ),
    )
    display_attrs = ("status", "service_type", "environment", "hostname", "port")


@register_search
class CertificateIndex(SearchIndex):
    model = Certificate
    fields = _existing(
        Certificate,
        (
            ("name", 100),
            ("serial_number", 50),
            ("fingerprint_sha256", 50),
            ("public_key_fingerprint", 60),
            ("subject", 200),
            ("issuer", 300),
            ("sans", 300),
            ("subject_alt_names", 300),
            ("description", 500),
            ("comments", 5000),
        ),
    )


@register_search
class PrivateKeyIndex(SearchIndex):
    model = PrivateKey
    fields = _existing(
        PrivateKey,
        (
            ("name", 100),
            ("fingerprint_sha256", 50),
            ("material_fingerprint", 50),
            ("public_key_fingerprint", 60),
            ("description", 500),
            ("comments", 5000),
        ),
    )


@register_search
class CSRIndex(SearchIndex):
    model = CSR
    fields = _existing(
        CSR,
        (
            ("name", 100),
            ("fingerprint_sha256", 50),
            ("public_key_fingerprint", 60),
            ("subject", 200),
            ("sans", 300),
            ("subject_alt_names", 300),
            ("description", 500),
            ("comments", 5000),
        ),
    )


@register_search
class BundleIndex(SearchIndex):
    model = Bundle
    fields = _existing(
        Bundle,
        (
            ("name", 100),
            ("identity_fingerprint", 50),
            ("description", 500),
            ("comments", 5000),
        ),
    )


@register_search
class CertificatePolicyIndex(SearchIndex):
    model = CertificatePolicy
    fields = _existing(CertificatePolicy, (("name", 100), ("description", 500), ("comments", 5000)))


@register_search
class HealthFindingIndex(SearchIndex):
    model = HealthFinding
    fields = _existing(
        HealthFinding,
        (("fingerprint", 50), ("code", 100), ("summary", 100), ("category", 300), ("description", 500), ("comments", 5000)),
    )
    display_attrs = ("severity", "status", "category")


@register_search
class ObjectLinkIndex(SearchIndex):
    model = ObjectLink
    fields = _existing(ObjectLink, (("label", 100), ("relationship", 200), ("description", 500), ("comments", 5000)))


@register_search
class AlertRuleIndex(SearchIndex):
    model = AlertRule
    fields = _existing(AlertRule, (("name", 100), ("description", 500), ("comments", 5000)))


@register_search
class AlertChannelIndex(SearchIndex):
    model = AlertChannel
    fields = _existing(AlertChannel, (("name", 100), ("subject_prefix", 300), ("description", 500), ("comments", 5000)))


@register_search
class AlertEventIndex(SearchIndex):
    model = AlertEvent
    fields = _existing(AlertEvent, (("error", 300), ("description", 500), ("comments", 5000)))
