from django.db import transaction
from rest_framework import serializers
from netbox.api.serializers import PrimaryModelSerializer
from netbox.models import NetBoxModel
from netbox.models.features import model_is_public

from ..models import ArtifactGroup, Bundle, Certificate, CSR, PrivateKey
from ..models_v1 import (
    AlertChannel,
    AlertEvent,
    AlertRule,
    CertificatePolicy,
    HealthFinding,
    ObjectLink,
    Service,
)
from ..services.secret_v1 import encrypt_json, encrypt_text


class ServiceSerializer(PrimaryModelSerializer):
    class Meta:
        model = Service
        fields = (
            "id", "url", "display_url", "display", "name", "status", "service_type", "other_type",
            "deployment", "deployment_metadata", "environment", "protocol", "primary_url", "additional_urls",
            "hostname", "port", "sni_name", "criticality", "external_reference", "contact",
            "enabled", "policy", "groups", "certificates", "private_keys", "csrs", "bundles",
            "owner", "description", "comments", "tags", "custom_fields",
            "created", "last_updated",
        )
        brief_fields = ("id", "url", "display_url", "display", "name", "status", "service_type", "hostname")


class CertificatePolicySerializer(PrimaryModelSerializer):
    class Meta:
        model = CertificatePolicy
        fields = (
            "id", "url", "display_url", "display", "name", "enabled", "minimum_rsa_bits", "allowed_key_types",
            "allowed_signature_algorithms", "allowed_curves", "max_validity_days",
            "require_san", "allow_wildcards", "allow_ca", "allowed_issuers",
            "forbid_key_reuse", "certificates", "csrs", "bundles",
            "owner", "description", "comments", "tags", "custom_fields",
            "created", "last_updated",
        )
        brief_fields = ("id", "url", "display_url", "display", "name", "enabled")


class ObjectLinkSerializer(PrimaryModelSerializer):
    source_display = serializers.SerializerMethodField()
    target_display = serializers.SerializerMethodField()

    class Meta:
        model = ObjectLink
        fields = (
            "id", "url", "display_url", "display", "source_type", "source_object_id", "source_display",
            "target_type", "target_object_id", "target_display", "relationship", "label",
            "automatic", "enabled", "owner", "description", "comments", "tags", "custom_fields",
            "created", "last_updated",
        )
        brief_fields = ("id", "url", "display_url", "display", "relationship", "automatic", "source_display", "target_display")
        read_only_fields = ("automatic",)

    def get_source_display(self, obj):
        return str(obj.source) if obj.source is not None else None

    def get_target_display(self, obj):
        return str(obj.target) if obj.target is not None else None

    def validate(self, attrs):
        attrs = super().validate(attrs)
        source_type = attrs.get("source_type", getattr(self.instance, "source_type", None))
        source_object_id = attrs.get("source_object_id", getattr(self.instance, "source_object_id", None))
        target_type = attrs.get("target_type", getattr(self.instance, "target_type", None))
        target_object_id = attrs.get("target_object_id", getattr(self.instance, "target_object_id", None))

        errors = {}
        endpoints = (
            ("source", source_type, source_object_id),
            ("target", target_type, target_object_id),
        )
        for prefix, content_type, object_id in endpoints:
            model = content_type.model_class() if content_type is not None else None
            if (
                model is None
                or not isinstance(model, type)
                or not issubclass(model, NetBoxModel)
                or not model_is_public(model)
            ):
                errors[f"{prefix}_type"] = "Select a public NetBox/plugin object model."
                continue
            if not object_id or not model._default_manager.filter(pk=object_id).exists():
                errors[f"{prefix}_object_id"] = "The selected object does not exist."

        if (
            source_type is not None
            and target_type is not None
            and source_type.pk == target_type.pk
            and source_object_id == target_object_id
        ):
            errors["target_object_id"] = "An object cannot be linked to itself."

        if errors:
            raise serializers.ValidationError(errors)
        return attrs


class HealthFindingSerializer(PrimaryModelSerializer):
    affected_display = serializers.SerializerMethodField()
    related_display = serializers.SerializerMethodField()

    class Meta:
        model = HealthFinding
        fields = (
            "id", "url", "display_url", "display", "code", "category", "severity", "status",
            "object_type", "object_id", "affected_display",
            "related_type", "related_object_id", "related_display",
            "summary", "details", "evidence", "fingerprint",
            "first_detected", "last_detected", "resolved_at",
            "owner", "description", "comments", "tags", "custom_fields",
            "created", "last_updated",
        )
        brief_fields = ("id", "url", "display_url", "display", "severity", "status", "code", "summary")
        read_only_fields = (
            "code", "category", "severity", "object_type", "object_id",
            "related_type", "related_object_id", "summary", "details", "evidence",
            "fingerprint", "first_detected", "last_detected", "resolved_at",
        )

    def get_affected_display(self, obj):
        return str(obj.affected_object) if obj.affected_object is not None else None

    def get_related_display(self, obj):
        return str(obj.related_object) if obj.related_object is not None else None


class AlertChannelSerializer(PrimaryModelSerializer):
    smtp_password = serializers.CharField(write_only=True, required=False, allow_blank=True)
    smtp_password_configured = serializers.SerializerMethodField()
    webhook_url = serializers.URLField(write_only=True, required=False, allow_blank=True)
    webhook_headers = serializers.JSONField(write_only=True, required=False)
    webhook_configured = serializers.SerializerMethodField()

    class Meta:
        model = AlertChannel
        fields = (
            "id", "url", "display_url", "display", "name", "enabled", "channel_type", "recipients",
            "smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_password_configured",
            "smtp_use_tls", "smtp_use_ssl", "from_email",
            "webhook_url", "webhook_headers", "webhook_configured", "subject_prefix",
            "owner", "description", "comments", "tags", "custom_fields",
            "created", "last_updated",
        )
        brief_fields = ("id", "url", "display_url", "display", "name", "enabled", "channel_type")

    def get_smtp_password_configured(self, obj):
        return bool(obj.smtp_password_encrypted)

    def get_webhook_configured(self, obj):
        return bool(obj.webhook_url_encrypted)

    def validate(self, attrs):
        attrs = super().validate(attrs)
        channel_type = attrs.get("channel_type", getattr(self.instance, "channel_type", None))
        recipients = attrs.get("recipients", getattr(self.instance, "recipients", []))
        webhook_url = attrs.get("webhook_url", None)
        configured_webhook = bool(getattr(self.instance, "webhook_url_encrypted", ""))

        if channel_type == "email":
            errors = {}
            if not recipients:
                errors["recipients"] = "At least one recipient is required for an email channel."
            smtp_host = attrs.get("smtp_host", getattr(self.instance, "smtp_host", ""))
            if not smtp_host:
                errors["smtp_host"] = "SMTP host is required for an email channel."
            use_tls = attrs.get("smtp_use_tls", getattr(self.instance, "smtp_use_tls", True))
            use_ssl = attrs.get("smtp_use_ssl", getattr(self.instance, "smtp_use_ssl", False))
            if use_tls and use_ssl:
                errors["smtp_use_ssl"] = "TLS and SSL cannot both be enabled."
            if errors:
                raise serializers.ValidationError(errors)
        if channel_type == "webhook" and webhook_url in (None, "") and not configured_webhook:
            raise serializers.ValidationError({"webhook_url": "Webhook URL is required for a webhook channel."})
        return attrs

    def create(self, validated_data):
        smtp_password = validated_data.pop("smtp_password", "")
        webhook_url = validated_data.pop("webhook_url", "")
        webhook_headers = validated_data.pop("webhook_headers", {})
        with transaction.atomic():
            instance = super().create(validated_data)
            instance.smtp_password_encrypted = encrypt_text(smtp_password)
            instance.webhook_url_encrypted = encrypt_text(webhook_url)
            instance.webhook_headers_encrypted = encrypt_json(webhook_headers)
            instance.full_clean()
            instance.save()
        return instance

    def update(self, instance, validated_data):
        smtp_password = validated_data.pop("smtp_password", None)
        webhook_url = validated_data.pop("webhook_url", None)
        webhook_headers = validated_data.pop("webhook_headers", None)
        with transaction.atomic():
            instance = super().update(instance, validated_data)
            if smtp_password not in (None, ""):
                instance.smtp_password_encrypted = encrypt_text(smtp_password)
            if webhook_url is not None:
                instance.webhook_url_encrypted = encrypt_text(webhook_url)
            if webhook_headers is not None:
                instance.webhook_headers_encrypted = encrypt_json(webhook_headers)
            instance.full_clean()
            instance.save()
        return instance


class AlertRuleSerializer(PrimaryModelSerializer):
    class Meta:
        model = AlertRule
        fields = (
            "id", "url", "display_url", "display", "name", "enabled", "finding_codes", "categories",
            "severities", "statuses", "object_types", "tag_names", "owner_ids",
            "expiration_days", "cooldown_minutes", "repeat_minutes",
            "notify_on_recovery", "channels", "services", "policies", "groups",
            "owner", "description", "comments", "tags", "custom_fields",
            "created", "last_updated",
        )
        brief_fields = ("id", "url", "display_url", "display", "name", "enabled")


class AlertEventSerializer(PrimaryModelSerializer):
    class Meta:
        model = AlertEvent
        fields = (
            "id", "url", "display_url", "display", "rule", "channel", "finding", "status",
            "delivered_at", "error", "payload_summary", "owner", "description",
            "comments", "tags", "custom_fields", "created", "last_updated",
        )
        brief_fields = ("id", "url", "display_url", "display", "status", "rule", "channel", "finding", "created")
