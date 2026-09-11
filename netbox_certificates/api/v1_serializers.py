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
from ..services.secret_v1 import SecretConfigurationError, encrypt_json, encrypt_text
from ..permissions import action_queryset, object_allowed
from .serializers import CertificateSerializer, VisibleRelationshipsMixin


class CACertificateSerializer(CertificateSerializer):
    def validate(self, attrs):
        attrs = super().validate(attrs)
        if not attrs.get("is_ca", getattr(self.instance, "is_ca", False)):
            raise serializers.ValidationError({"material": "Only CA certificates (Basic Constraints CA=true) are accepted."})
        return attrs


class ServiceSerializer(VisibleRelationshipsMixin, PrimaryModelSerializer):
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


class CertificatePolicySerializer(VisibleRelationshipsMixin, PrimaryModelSerializer):
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


class ObjectLinkSerializer(VisibleRelationshipsMixin, PrimaryModelSerializer):
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
        return str(obj.source) if object_allowed(self.context["request"].user, obj.source) else None

    def get_target_display(self, obj):
        return str(obj.target) if object_allowed(self.context["request"].user, obj.target) else None

    def validate(self, attrs):
        attrs = super().validate(attrs)
        if self.instance and self.instance.automatic:
            raise serializers.ValidationError("Automatic cryptographic links are managed by reconciliation.")
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
            if not object_id or not action_queryset(model, self.context["request"].user).filter(pk=object_id).exists():
                errors[f"{prefix}_object_id"] = "The selected object does not exist or is not visible to you."

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


class HealthFindingSerializer(VisibleRelationshipsMixin, PrimaryModelSerializer):
    affected_display = serializers.SerializerMethodField()
    related_display = serializers.SerializerMethodField()

    def validate(self, attrs):
        if self.instance and "status" in attrs and attrs["status"] != self.instance.status:
            action = {"acknowledged": "acknowledge", "ignored": "ignore", "resolved": "resolve", "active": "change"}[attrs["status"]]
            if not object_allowed(self.context["request"].user, self.instance, action):
                raise serializers.ValidationError({"status": f"{action.capitalize()} permission is required for this finding."})
        return super().validate(attrs)

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
        return str(obj.affected_object) if object_allowed(self.context["request"].user, obj.affected_object) else None

    def get_related_display(self, obj):
        return str(obj.related_object) if object_allowed(self.context["request"].user, obj.related_object) else None


class AlertChannelSerializer(VisibleRelationshipsMixin, PrimaryModelSerializer):
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
            "smtp_use_tls", "smtp_use_ssl", "smtp_verify_tls", "webhook_verify_tls", "from_email",
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
        # NetBox runs model.full_clean() here, so write-only transport inputs
        # must become real encrypted model fields before delegating to it.
        smtp_password = attrs.pop("smtp_password", None)
        webhook_url = attrs.pop("webhook_url", None)
        webhook_headers = attrs.pop("webhook_headers", None)
        channel_type = attrs.get("channel_type", getattr(self.instance, "channel_type", None))
        recipients = attrs.get("recipients", getattr(self.instance, "recipients", []))
        if channel_type == "email" and not recipients:
            raise serializers.ValidationError({"recipients": "At least one recipient is required for an email channel."})
        if channel_type == "webhook" and not (webhook_url or getattr(self.instance, "webhook_url_encrypted", "")):
            raise serializers.ValidationError({"webhook_url": "Webhook URL is required for a webhook channel."})
        if webhook_headers is not None and (not isinstance(webhook_headers, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) or "\n" in k + v or "\r" in k + v
            for k, v in webhook_headers.items()
        )):
            raise serializers.ValidationError({"webhook_headers": "Enter an object of header names and string values without newlines."})
        try:
            if smtp_password:
                attrs["smtp_password_encrypted"] = encrypt_text(smtp_password)
            if webhook_url:
                attrs["webhook_url_encrypted"] = encrypt_text(webhook_url)
            if webhook_headers is not None:
                attrs["webhook_headers_encrypted"] = encrypt_json(webhook_headers)
        except SecretConfigurationError as exc:
            raise serializers.ValidationError({"detail": str(exc)}) from exc
        return super().validate(attrs)

    def create(self, validated_data):
        with transaction.atomic():
            return super().create(validated_data)

    def update(self, instance, validated_data):
        with transaction.atomic():
            return super().update(instance, validated_data)


class AlertRuleSerializer(VisibleRelationshipsMixin, PrimaryModelSerializer):
    class Meta:
        model = AlertRule
        fields = (
            "id", "url", "display_url", "display", "name", "enabled", "finding_codes", "categories",
            "severities", "statuses", "object_types", "tag_names", "owner_ids",
            "cooldown_minutes", "repeat_minutes",
            "notify_on_recovery", "channels", "services", "policies", "groups",
            "owner", "description", "comments", "tags", "custom_fields",
            "created", "last_updated",
        )
        brief_fields = ("id", "url", "display_url", "display", "name", "enabled")


class AlertEventSerializer(VisibleRelationshipsMixin, PrimaryModelSerializer):
    class Meta:
        model = AlertEvent
        fields = (
            "id", "url", "display_url", "display", "rule", "channel", "finding", "status",
            "delivered_at", "error", "payload_summary", "owner", "description",
            "comments", "tags", "custom_fields", "created", "last_updated",
        )
        brief_fields = ("id", "url", "display_url", "display", "status", "rule", "channel", "finding", "created")
        read_only_fields = ("rule", "channel", "finding", "status", "delivered_at", "error", "payload_summary")
