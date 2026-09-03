import json

import django_filters
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from netbox.filtersets import PrimaryModelFilterSet
from utilities.filtersets import register_filterset

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


def _json_value_filter(queryset, field_name, value):
    if value in (None, ""):
        return queryset
    try:
        parsed = json.loads(value)
    except (TypeError, json.JSONDecodeError):
        parsed = value
    if isinstance(parsed, (dict, list)):
        return queryset.filter(**{f"{field_name}__contains": parsed})
    return queryset.filter(**{f"{field_name}__contains": [parsed]})


@register_filterset
class ServiceFilterSet(PrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    status = django_filters.MultipleChoiceFilter(choices=Service._meta.get_field("status").choices)
    service_type = django_filters.MultipleChoiceFilter(choices=Service._meta.get_field("service_type").choices)
    deployment = django_filters.CharFilter(field_name="deployment", lookup_expr="icontains")
    deployment_metadata = django_filters.CharFilter(method="filter_deployment_metadata")
    environment = django_filters.MultipleChoiceFilter(choices=Service._meta.get_field("environment").choices)
    criticality = django_filters.MultipleChoiceFilter(choices=Service._meta.get_field("criticality").choices)
    groups_id = django_filters.ModelMultipleChoiceFilter(field_name="groups", queryset=ArtifactGroup.objects.all())
    certificate_id = django_filters.ModelMultipleChoiceFilter(field_name="certificates", queryset=Certificate.objects.all())
    private_key_id = django_filters.ModelMultipleChoiceFilter(field_name="private_keys", queryset=PrivateKey.objects.all())
    csr_id = django_filters.ModelMultipleChoiceFilter(field_name="csrs", queryset=CSR.objects.all())
    bundle_id = django_filters.ModelMultipleChoiceFilter(field_name="bundles", queryset=Bundle.objects.all())
    policy_id = django_filters.ModelMultipleChoiceFilter(field_name="policy", queryset=CertificatePolicy.objects.all())
    additional_url = django_filters.CharFilter(method="filter_additional_url")

    class Meta:
        model = Service
        fields = (
            "id",
            "name",
            "status",
            "service_type",
            "other_type",
            "deployment",
            "deployment_metadata",
            "environment",
            "protocol",
            "primary_url",
            "hostname",
            "port",
            "sni_name",
            "criticality",
            "external_reference",
            "contact",
            "enabled",
            "policy",
            "description",
        )

    def search(self, queryset, name, value):
        value = value.strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(description__icontains=value)
            | Q(comments__icontains=value)
            | Q(primary_url__icontains=value)
            | Q(hostname__icontains=value)
            | Q(sni_name__icontains=value)
            | Q(external_reference__icontains=value)
            | Q(contact__icontains=value)
        ).distinct()

    def filter_additional_url(self, queryset, name, value):
        return _json_value_filter(queryset, "additional_urls", value)

    def filter_deployment_metadata(self, queryset, name, value):
        value = str(value or "").strip()
        if not value:
            return queryset
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return queryset.none()
        if not isinstance(parsed, dict):
            return queryset.none()
        return queryset.filter(deployment_metadata__contains=parsed)


@register_filterset
class CertificatePolicyFilterSet(PrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    allowed_key_types = django_filters.CharFilter(method="filter_json")
    allowed_signature_algorithms = django_filters.CharFilter(method="filter_json")
    allowed_curves = django_filters.CharFilter(method="filter_json")
    allowed_issuers = django_filters.CharFilter(method="filter_json")
    certificate_id = django_filters.ModelMultipleChoiceFilter(field_name="certificates", queryset=Certificate.objects.all())
    csr_id = django_filters.ModelMultipleChoiceFilter(field_name="csrs", queryset=CSR.objects.all())
    bundle_id = django_filters.ModelMultipleChoiceFilter(field_name="bundles", queryset=Bundle.objects.all())

    class Meta:
        model = CertificatePolicy
        fields = (
            "id",
            "name",
            "enabled",
            "minimum_rsa_bits",
            "max_validity_days",
            "require_san",
            "allow_wildcards",
            "allow_ca",
            "forbid_key_reuse",
            "description",
        )

    def search(self, queryset, name, value):
        value = value.strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(description__icontains=value)
            | Q(comments__icontains=value)
        )

    def filter_json(self, queryset, name, value):
        return _json_value_filter(queryset, name, value)


@register_filterset
class HealthFindingFilterSet(PrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    details = django_filters.CharFilter(method="filter_json")
    evidence = django_filters.CharFilter(method="filter_json")
    object_type_id = django_filters.ModelMultipleChoiceFilter(
        field_name="object_type",
        queryset=ContentType.objects.all(),
    )
    related_type_id = django_filters.ModelMultipleChoiceFilter(
        field_name="related_type",
        queryset=ContentType.objects.all(),
    )

    class Meta:
        model = HealthFinding
        fields = (
            "id",
            "code",
            "category",
            "severity",
            "status",
            "object_type",
            "object_id",
            "related_type",
            "related_object_id",
            "summary",
            "fingerprint",
            "first_detected",
            "last_detected",
            "resolved_at",
            "description",
        )

    def search(self, queryset, name, value):
        value = value.strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(code__icontains=value)
            | Q(category__icontains=value)
            | Q(summary__icontains=value)
            | Q(description__icontains=value)
            | Q(comments__icontains=value)
            | Q(fingerprint__icontains=value)
        )

    def filter_json(self, queryset, name, value):
        return _json_value_filter(queryset, name, value)


@register_filterset
class ObjectLinkFilterSet(PrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    source_type_id = django_filters.ModelMultipleChoiceFilter(
        field_name="source_type",
        queryset=ContentType.objects.all(),
    )
    target_type_id = django_filters.ModelMultipleChoiceFilter(
        field_name="target_type",
        queryset=ContentType.objects.all(),
    )

    class Meta:
        model = ObjectLink
        fields = (
            "id",
            "source_type",
            "source_object_id",
            "target_type",
            "target_object_id",
            "relationship",
            "label",
            "automatic",
            "enabled",
            "description",
        )

    def search(self, queryset, name, value):
        value = value.strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(relationship__icontains=value)
            | Q(label__icontains=value)
            | Q(description__icontains=value)
            | Q(comments__icontains=value)
        )


@register_filterset
class AlertChannelFilterSet(PrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    recipients = django_filters.CharFilter(method="filter_recipients")

    class Meta:
        model = AlertChannel
        fields = (
            "id",
            "name",
            "enabled",
            "channel_type",
            "smtp_host",
            "smtp_port",
            "smtp_username",
            "smtp_use_tls",
            "smtp_use_ssl",
            "from_email",
            "subject_prefix",
            "description",
        )

    def search(self, queryset, name, value):
        value = value.strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(smtp_host__icontains=value)
            | Q(smtp_username__icontains=value)
            | Q(from_email__icontains=value)
            | Q(subject_prefix__icontains=value)
            | Q(description__icontains=value)
            | Q(comments__icontains=value)
        )

    def filter_recipients(self, queryset, name, value):
        return _json_value_filter(queryset, "recipients", value)


@register_filterset
class AlertRuleFilterSet(PrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    finding_codes = django_filters.CharFilter(method="filter_json")
    categories = django_filters.CharFilter(method="filter_json")
    severities = django_filters.CharFilter(method="filter_json")
    statuses = django_filters.CharFilter(method="filter_json")
    object_types = django_filters.CharFilter(method="filter_json")
    tag_names = django_filters.CharFilter(method="filter_json")
    owner_ids = django_filters.CharFilter(method="filter_json")
    channel_id = django_filters.ModelMultipleChoiceFilter(field_name="channels", queryset=AlertChannel.objects.all())
    service_id = django_filters.ModelMultipleChoiceFilter(field_name="services", queryset=Service.objects.all())
    policy_id = django_filters.ModelMultipleChoiceFilter(field_name="policies", queryset=CertificatePolicy.objects.all())
    group_id = django_filters.ModelMultipleChoiceFilter(field_name="groups", queryset=ArtifactGroup.objects.all())

    class Meta:
        model = AlertRule
        fields = (
            "id",
            "name",
            "enabled",
            "expiration_days",
            "cooldown_minutes",
            "repeat_minutes",
            "notify_on_recovery",
            "description",
        )

    def search(self, queryset, name, value):
        value = value.strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(description__icontains=value)
            | Q(comments__icontains=value)
        ).distinct()

    def filter_json(self, queryset, name, value):
        return _json_value_filter(queryset, name, value)


@register_filterset
class AlertEventFilterSet(PrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    payload_summary = django_filters.CharFilter(method="filter_payload")
    rule_id = django_filters.ModelMultipleChoiceFilter(field_name="rule", queryset=AlertRule.objects.all())
    channel_id = django_filters.ModelMultipleChoiceFilter(field_name="channel", queryset=AlertChannel.objects.all())
    finding_id = django_filters.ModelMultipleChoiceFilter(field_name="finding", queryset=HealthFinding.objects.all())

    class Meta:
        model = AlertEvent
        fields = (
            "id",
            "rule",
            "channel",
            "finding",
            "status",
            "delivered_at",
            "error",
            "description",
        )

    def search(self, queryset, name, value):
        value = value.strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(error__icontains=value)
            | Q(description__icontains=value)
            | Q(comments__icontains=value)
            | Q(rule__name__icontains=value)
            | Q(channel__name__icontains=value)
        ).distinct()

    def filter_payload(self, queryset, name, value):
        if value in (None, ""):
            return queryset
        try:
            parsed = json.loads(value)
        except (TypeError, json.JSONDecodeError):
            return queryset
        return queryset.filter(payload_summary__contains=parsed)
