"""NetBox 4.5 Strawberry GraphQL schema for the public 1.0 object model.

The GraphQL surface is metadata-oriented. Raw cryptographic material, encrypted
private-key/archive material, alert transport secrets, and pre-1.0 internal
models are intentionally excluded.
"""

import strawberry
import strawberry_django
from netbox.graphql.types import NetBoxObjectType

from .models import ArtifactGroup, Bundle, Certificate, CSR, PrivateKey
from .models_v1 import (
    AlertChannel,
    AlertEvent,
    AlertRule,
    CertificatePolicy,
    HealthFinding,
    ObjectLink,
    Service,
)


_SENSITIVE_FIELD_NAMES = {
    "material",
    "encrypted_material",
    "raw_material",
    "password",
    "preserved_archive",
    "preserved_archive_encrypted",
    "encrypted_archive",
    "archive_encrypted",
    "smtp_password_encrypted",
    "webhook_url_encrypted",
    "webhook_headers_encrypted",
}

# The pre-1.0 root identity is deliberately internal in 1.0. Certificate.authority
# remains an implementation relationship used by chain resolution, but it is not
# a public GraphQL relation.
_INTERNAL_RELATION_FIELDS = {"authority"}


def _safe_fields(model):
    """Return public model fields without secrets or internal relationship types."""

    result = []
    for field in model._meta.get_fields():
        name = getattr(field, "name", None)
        if not name or getattr(field, "auto_created", False):
            continue
        if name in _SENSITIVE_FIELD_NAMES or name in _INTERNAL_RELATION_FIELDS:
            continue
        if "encrypted" in name.lower() or "secret" in name.lower() or "password" in name.lower():
            continue
        # GenericForeignKey is virtual and is represented by its ContentType/object
        # ID fields instead of trying to synthesize arbitrary GraphQL object unions.
        if not getattr(field, "concrete", False) and not getattr(field, "many_to_many", False):
            continue
        result.append(name)
    return tuple(dict.fromkeys(result))


@strawberry_django.type(ArtifactGroup, fields=_safe_fields(ArtifactGroup))
class ArtifactGroupType(NetBoxObjectType):
    pass


@strawberry_django.type(Certificate, fields=_safe_fields(Certificate))
class CertificateType(NetBoxObjectType):
    pass


@strawberry_django.type(PrivateKey, fields=_safe_fields(PrivateKey))
class PrivateKeyType(NetBoxObjectType):
    """Metadata only. Encrypted/raw private-key material is never in GraphQL."""


@strawberry_django.type(CSR, fields=_safe_fields(CSR))
class CSRType(NetBoxObjectType):
    pass


@strawberry_django.type(Bundle, fields=_safe_fields(Bundle))
class BundleType(NetBoxObjectType):
    """Bundle metadata/relationships only; preserved archive bytes are excluded."""


@strawberry_django.type(Service, fields=_safe_fields(Service))
class ServiceType(NetBoxObjectType):
    pass


@strawberry_django.type(CertificatePolicy, fields=_safe_fields(CertificatePolicy))
class CertificatePolicyType(NetBoxObjectType):
    pass


@strawberry_django.type(HealthFinding, fields=_safe_fields(HealthFinding))
class HealthFindingType(NetBoxObjectType):
    pass


@strawberry_django.type(ObjectLink, fields=_safe_fields(ObjectLink))
class ObjectLinkType(NetBoxObjectType):
    pass


@strawberry_django.type(AlertChannel, fields=_safe_fields(AlertChannel))
class AlertChannelType(NetBoxObjectType):
    """Alert secrets are deliberately omitted."""


@strawberry_django.type(AlertRule, fields=_safe_fields(AlertRule))
class AlertRuleType(NetBoxObjectType):
    pass


@strawberry_django.type(AlertEvent, fields=_safe_fields(AlertEvent))
class AlertEventType(NetBoxObjectType):
    pass


@strawberry.type(name="Query")
class NetBoxCertificatesQuery:
    artifact_group: ArtifactGroupType = strawberry_django.field()
    artifact_group_list: list[ArtifactGroupType] = strawberry_django.field()

    certificate: CertificateType = strawberry_django.field()
    certificate_list: list[CertificateType] = strawberry_django.field()

    private_key: PrivateKeyType = strawberry_django.field()
    private_key_list: list[PrivateKeyType] = strawberry_django.field()

    csr: CSRType = strawberry_django.field()
    csr_list: list[CSRType] = strawberry_django.field()

    bundle: BundleType = strawberry_django.field()
    bundle_list: list[BundleType] = strawberry_django.field()

    service: ServiceType = strawberry_django.field()
    service_list: list[ServiceType] = strawberry_django.field()

    certificate_policy: CertificatePolicyType = strawberry_django.field()
    certificate_policy_list: list[CertificatePolicyType] = strawberry_django.field()

    health_finding: HealthFindingType = strawberry_django.field()
    health_finding_list: list[HealthFindingType] = strawberry_django.field()

    object_link: ObjectLinkType = strawberry_django.field()
    object_link_list: list[ObjectLinkType] = strawberry_django.field()

    alert_channel: AlertChannelType = strawberry_django.field()
    alert_channel_list: list[AlertChannelType] = strawberry_django.field()

    alert_rule: AlertRuleType = strawberry_django.field()
    alert_rule_list: list[AlertRuleType] = strawberry_django.field()

    alert_event: AlertEventType = strawberry_django.field()
    alert_event_list: list[AlertEventType] = strawberry_django.field()


schema = [NetBoxCertificatesQuery]
