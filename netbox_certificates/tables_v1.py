import django_tables2 as tables
from netbox.tables import PrimaryModelTable, columns

from .models_v1 import AlertChannel, AlertEvent, AlertRule, CertificatePolicy, HealthFinding, ObjectLink, Service


class ServiceTable(PrimaryModelTable):
    name = tables.Column(linkify=True)
    policy = tables.Column(linkify=True)
    groups = columns.ManyToManyColumn(linkify_item=True)

    class Meta(PrimaryModelTable.Meta):
        model = Service
        fields = (
            "pk", "id", "name", "status", "service_type", "deployment", "deployment_metadata", "environment",
            "primary_url", "hostname", "port", "sni_name", "criticality", "policy",
            "groups", "enabled", "description", "owner", "tags", "last_updated",
        )
        default_columns = (
            "pk", "name", "status", "service_type", "deployment", "environment",
            "hostname", "port", "criticality", "policy",
        )


class CertificatePolicyTable(PrimaryModelTable):
    name = tables.Column(linkify=True)

    class Meta(PrimaryModelTable.Meta):
        model = CertificatePolicy
        fields = (
            "pk", "id", "name", "enabled", "minimum_rsa_bits", "max_validity_days",
            "require_san", "allow_wildcards", "allow_ca", "forbid_key_reuse",
            "description", "owner", "tags", "last_updated",
        )
        default_columns = ("pk", "name", "enabled", "minimum_rsa_bits", "max_validity_days", "allow_wildcards", "allow_ca")


class HealthFindingTable(PrimaryModelTable):
    summary = tables.Column(linkify=True)
    affected_object = tables.Column(orderable=False)
    related_object = tables.Column(orderable=False)

    class Meta(PrimaryModelTable.Meta):
        model = HealthFinding
        fields = (
            "pk", "id", "severity", "status", "category", "code", "summary",
            "affected_object", "related_object", "first_detected", "last_detected",
            "resolved_at", "owner", "tags",
        )
        default_columns = (
            "pk", "severity", "status", "category", "summary",
            "affected_object", "related_object", "last_detected",
        )


class ObjectLinkTable(PrimaryModelTable):
    source = tables.Column(orderable=False)
    target = tables.Column(orderable=False)

    class Meta(PrimaryModelTable.Meta):
        model = ObjectLink
        fields = (
            "pk", "id", "source", "target", "relationship", "label", "automatic", "enabled",
            "description", "owner", "tags", "last_updated",
        )
        default_columns = ("pk", "source", "target", "relationship", "label", "automatic", "enabled")


class AlertChannelTable(PrimaryModelTable):
    name = tables.Column(linkify=True)

    class Meta(PrimaryModelTable.Meta):
        model = AlertChannel
        fields = (
            "pk", "id", "name", "enabled", "channel_type", "subject_prefix",
            "description", "owner", "tags", "last_updated",
        )
        default_columns = ("pk", "name", "enabled", "channel_type", "subject_prefix")


class AlertRuleTable(PrimaryModelTable):
    name = tables.Column(linkify=True)
    channels = columns.ManyToManyColumn(linkify_item=True)
    services = columns.ManyToManyColumn(linkify_item=True)
    policies = columns.ManyToManyColumn(linkify_item=True)
    groups = columns.ManyToManyColumn(linkify_item=True)

    class Meta(PrimaryModelTable.Meta):
        model = AlertRule
        fields = (
            "pk", "id", "name", "enabled", "channels", "services", "policies", "groups",
            "expiration_days", "cooldown_minutes", "repeat_minutes", "notify_on_recovery",
            "description", "owner", "tags", "last_updated",
        )
        default_columns = ("pk", "name", "enabled", "channels", "cooldown_minutes", "repeat_minutes")


class AlertEventTable(PrimaryModelTable):
    class Meta(PrimaryModelTable.Meta):
        model = AlertEvent
        fields = (
            "pk", "id", "status", "rule", "channel", "finding", "delivered_at",
            "error", "created", "owner", "tags",
        )
        default_columns = ("pk", "status", "rule", "channel", "finding", "delivered_at", "created")
