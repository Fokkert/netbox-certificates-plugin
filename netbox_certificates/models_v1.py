from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django.db import models
from taggit.managers import TaggableManager
from extras.managers import NetBoxTaggableManager
from django.urls import reverse
from django.utils import timezone
from netbox.models import NetBoxModel, PrimaryModel
from netbox.models.features import model_is_public

from .choices_v1 import (
    AlertChannelTypeChoices,
    AlertEventStatusChoices,
    FindingSeverityChoices,
    FindingStatusChoices,
    ServiceCriticalityChoices,
    ServiceEnvironmentChoices,
    ServiceStatusChoices,
    ServiceTypeChoices,
)


def default_alert_statuses():
    return [FindingStatusChoices.ACTIVE]


class CertificatePolicy(PrimaryModel):
    name = models.CharField(max_length=120, unique=True)
    enabled = models.BooleanField(default=True)
    minimum_rsa_bits = models.PositiveIntegerField(default=2048)
    allowed_key_types = models.JSONField(default=list, blank=True)
    allowed_signature_algorithms = models.JSONField(default=list, blank=True)
    allowed_curves = models.JSONField(default=list, blank=True)
    max_validity_days = models.PositiveIntegerField(blank=True, null=True)
    require_san = models.BooleanField(default=True)
    allow_wildcards = models.BooleanField(default=True)
    allow_ca = models.BooleanField(default=False)
    allowed_issuers = models.JSONField(default=list, blank=True)
    forbid_key_reuse = models.BooleanField(default=False)

    certificates = models.ManyToManyField(
        "netbox_certificates.Certificate",
        related_name="certificate_policies",
        blank=True,
    )
    csrs = models.ManyToManyField(
        "netbox_certificates.CSR",
        related_name="certificate_policies",
        blank=True,
    )
    bundles = models.ManyToManyField(
        "netbox_certificates.Bundle",
        related_name="certificate_policies",
        blank=True,
    )

    clone_fields = (
        "enabled",
        "minimum_rsa_bits",
        "allowed_key_types",
        "allowed_signature_algorithms",
        "allowed_curves",
        "max_validity_days",
        "require_san",
        "allow_wildcards",
        "allow_ca",
        "allowed_issuers",
        "forbid_key_reuse",
    )

    class Meta:
        ordering = ("name",)
        permissions = (
            ("archive_export_certificatepolicy", "Can archive-export certificate policies"),
        )

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:certificatepolicy", args=[self.pk])


class Service(PrimaryModel):
    tags = TaggableManager(
        through="extras.TaggedItem",
        ordering=("weight", "name"),
        manager=NetBoxTaggableManager,
        related_name="netbox_certificates_service_tagged+",
    )

    name = models.CharField(max_length=160, unique=True)
    status = models.CharField(max_length=32, choices=ServiceStatusChoices, default=ServiceStatusChoices.ACTIVE)
    service_type = models.CharField(max_length=64, choices=ServiceTypeChoices, default=ServiceTypeChoices.WEBSITE)
    other_type = models.CharField(max_length=120, blank=True)
    deployment = models.CharField(
        max_length=120,
        default="Generic TLS Endpoint",
        help_text="Deployment technology or pattern. Common values are suggested by the UI; custom values are allowed.",
    )
    deployment_metadata = models.JSONField(
        default=dict,
        blank=True,
        help_text="Optional deployment-specific metadata such as namespace, secret name, virtual host, ingress, or configuration reference.",
    )
    environment = models.CharField(
        max_length=32,
        choices=ServiceEnvironmentChoices,
        default=ServiceEnvironmentChoices.PRODUCTION,
    )
    protocol = models.CharField(max_length=32, default="https")
    primary_url = models.URLField(max_length=500, blank=True)
    additional_urls = models.JSONField(default=list, blank=True)
    hostname = models.CharField(max_length=255, blank=True)
    port = models.PositiveIntegerField(default=443)
    sni_name = models.CharField(max_length=255, blank=True)
    criticality = models.CharField(
        max_length=32,
        choices=ServiceCriticalityChoices,
        default=ServiceCriticalityChoices.MEDIUM,
    )
    external_reference = models.CharField(max_length=200, blank=True)
    contact = models.CharField(max_length=200, blank=True)
    enabled = models.BooleanField(default=True)

    policy = models.ForeignKey(
        CertificatePolicy,
        on_delete=models.PROTECT,
        related_name="services",
        blank=True,
        null=True,
    )
    groups = models.ManyToManyField(
        "netbox_certificates.ArtifactGroup",
        related_name="services",
        blank=True,
    )
    certificates = models.ManyToManyField(
        "netbox_certificates.Certificate",
        related_name="services",
        blank=True,
    )
    private_keys = models.ManyToManyField(
        "netbox_certificates.PrivateKey",
        related_name="services",
        blank=True,
    )
    csrs = models.ManyToManyField(
        "netbox_certificates.CSR",
        related_name="services",
        blank=True,
    )
    bundles = models.ManyToManyField(
        "netbox_certificates.Bundle",
        related_name="services",
        blank=True,
    )

    clone_fields = (
        "status",
        "service_type",
        "other_type",
        "deployment",
        "deployment_metadata",
        "environment",
        "protocol",
        "port",
        "criticality",
        "enabled",
        "policy",
        "groups",
    )

    class Meta:
        ordering = ("name",)
        default_related_name = "%(app_label)s_%(model_name)s_set"
        permissions = (
            ("archive_export_service", "Can archive-export services"),
        )

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        if self.service_type == ServiceTypeChoices.OTHER and not self.other_type.strip():
            raise ValidationError({"other_type": "Specify a type when Service Type is Other."})
        if self.port and self.port > 65535:
            raise ValidationError({"port": "Port must be between 1 and 65535."})
        if not isinstance(self.additional_urls, list):
            raise ValidationError({"additional_urls": "Additional URLs must be a JSON list."})
        if not isinstance(self.deployment_metadata, dict):
            raise ValidationError({"deployment_metadata": "Deployment metadata must be a JSON object."})
        validate_url = URLValidator()
        url_errors = []
        for value in self.additional_urls:
            if not isinstance(value, str):
                url_errors.append(f"{value!r} is not a URL string.")
                continue
            try:
                validate_url(value)
            except ValidationError:
                url_errors.append(f"{value!r} is not a valid URL.")
        if url_errors:
            raise ValidationError({"additional_urls": url_errors})

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:service", args=[self.pk])

    @property
    def endpoint_names(self):
        values = []
        for candidate in (self.sni_name, self.hostname):
            if candidate and candidate not in values:
                values.append(candidate)
        return values


class ObjectLink(PrimaryModel):
    source_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        related_name="+",
    )
    source_object_id = models.PositiveBigIntegerField()
    source = GenericForeignKey("source_type", "source_object_id")

    target_type = models.ForeignKey(
        ContentType,
        on_delete=models.CASCADE,
        related_name="+",
    )
    target_object_id = models.PositiveBigIntegerField()
    target = GenericForeignKey("target_type", "target_object_id")

    relationship = models.CharField(max_length=80, default="related")
    label = models.CharField(max_length=160, blank=True)
    enabled = models.BooleanField(default=True)
    automatic = models.BooleanField(
        default=False,
        help_text="True for relationships maintained by the internal cryptographic reconciliation engine.",
    )

    class Meta:
        ordering = ("source_type_id", "source_object_id", "target_type_id", "target_object_id")
        constraints = (
            models.UniqueConstraint(
                fields=("source_type", "source_object_id", "target_type", "target_object_id", "relationship"),
                name="netbox_certificates_v1_objectlink_unique",
            ),
        )
        indexes = (
            models.Index(fields=("source_type", "source_object_id"), name="nbcert_v1_link_src_idx"),
            models.Index(fields=("target_type", "target_object_id"), name="nbcert_v1_link_dst_idx"),
        )
        permissions = (
            ("archive_export_objectlink", "Can archive-export object links"),
        )

    def __str__(self):
        source = self.source or f"{self.source_type}:{self.source_object_id}"
        target = self.target or f"{self.target_type}:{self.target_object_id}"
        return f"{source} -> {target}"

    def clean(self):
        super().clean()
        if (
            self.source_type_id == self.target_type_id
            and self.source_object_id == self.target_object_id
        ):
            raise ValidationError("An object cannot be linked to itself.")

        errors = {}
        for prefix, content_type, object_id in (
            ("source", self.source_type, self.source_object_id),
            ("target", self.target_type, self.target_object_id),
        ):
            model = content_type.model_class() if content_type else None
            if (
                model is None
                or not isinstance(model, type)
                or not issubclass(model, NetBoxModel)
                or not model_is_public(model)
            ):
                errors[f"{prefix}_type"] = "Links are limited to public NetBox/plugin object models."
                continue
            if object_id and not model._default_manager.filter(pk=object_id).exists():
                errors[f"{prefix}_object_id"] = "The selected object does not exist."
        if errors:
            raise ValidationError(errors)

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:objectlink", args=[self.pk])


class HealthFinding(PrimaryModel):
    code = models.CharField(max_length=120)
    category = models.CharField(max_length=80)
    severity = models.CharField(max_length=32, choices=FindingSeverityChoices)
    status = models.CharField(max_length=32, choices=FindingStatusChoices, default=FindingStatusChoices.ACTIVE)

    object_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="+")
    object_id = models.PositiveBigIntegerField()
    affected_object = GenericForeignKey("object_type", "object_id")

    related_type = models.ForeignKey(
        ContentType,
        on_delete=models.SET_NULL,
        related_name="+",
        blank=True,
        null=True,
    )
    related_object_id = models.PositiveBigIntegerField(blank=True, null=True)
    related_object = GenericForeignKey("related_type", "related_object_id")

    summary = models.CharField(max_length=300)
    details = models.JSONField(default=dict, blank=True)
    evidence = models.JSONField(default=dict, blank=True)
    fingerprint = models.CharField(max_length=64, unique=True)
    first_detected = models.DateTimeField(default=timezone.now)
    last_detected = models.DateTimeField(default=timezone.now)
    resolved_at = models.DateTimeField(blank=True, null=True)

    class Meta:
        ordering = ("status", "-severity", "-last_detected")
        indexes = (
            models.Index(fields=("object_type", "object_id"), name="nbcert_v1_health_obj_idx"),
            models.Index(fields=("status", "severity"), name="nbcert_v1_health_state_idx"),
        )
        permissions = (
            ("run_healthscan_healthfinding", "Can run certificate health scans"),
            ("acknowledge_healthfinding", "Can acknowledge health findings"),
            ("ignore_healthfinding", "Can ignore health findings"),
            ("resolve_healthfinding", "Can resolve health findings"),
            ("archive_export_healthfinding", "Can archive-export health findings"),
        )

    def __str__(self):
        return f"{self.get_severity_display()}: {self.summary}"

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:healthfinding", args=[self.pk])


class AlertChannel(PrimaryModel):
    name = models.CharField(max_length=120, unique=True)
    enabled = models.BooleanField(default=True)
    channel_type = models.CharField(max_length=32, choices=AlertChannelTypeChoices)
    recipients = models.JSONField(default=list, blank=True)
    smtp_host = models.CharField(max_length=255, blank=True)
    smtp_port = models.PositiveIntegerField(default=587)
    smtp_username = models.CharField(max_length=255, blank=True)
    smtp_password_encrypted = models.TextField(blank=True)
    smtp_use_tls = models.BooleanField(default=True)
    smtp_use_ssl = models.BooleanField(default=False)
    from_email = models.EmailField(blank=True)
    webhook_url_encrypted = models.TextField(blank=True)
    webhook_headers_encrypted = models.TextField(blank=True)
    subject_prefix = models.CharField(max_length=120, default="[NetBox Certificates]")

    class Meta:
        ordering = ("name",)
        permissions = (
            ("test_alertchannel", "Can test alert channels"),
            ("archive_export_alertchannel", "Can archive-export alert channels"),
        )

    def __str__(self):
        return self.name

    def clean(self):
        super().clean()
        if self.channel_type == AlertChannelTypeChoices.EMAIL:
            errors = {}
            if not self.recipients:
                errors["recipients"] = "At least one recipient is required for an email channel."
            if not self.smtp_host:
                errors["smtp_host"] = "SMTP host is required for an email channel."
            if self.smtp_use_tls and self.smtp_use_ssl:
                errors["smtp_use_ssl"] = "TLS and SSL cannot both be enabled."
            if self.smtp_port and self.smtp_port > 65535:
                errors["smtp_port"] = "SMTP port must be between 1 and 65535."
            if errors:
                raise ValidationError(errors)
        # Webhook URL/header validation occurs in the UI/API serializers before
        # encrypted values are assigned. Requiring ciphertext here would reject
        # a valid newly-submitted webhook before the form has encrypted it.

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:alertchannel", args=[self.pk])


class AlertRule(PrimaryModel):
    name = models.CharField(max_length=120, unique=True)
    enabled = models.BooleanField(default=True)
    finding_codes = models.JSONField(default=list, blank=True)
    categories = models.JSONField(default=list, blank=True)
    severities = models.JSONField(default=list, blank=True)
    statuses = models.JSONField(default=default_alert_statuses, blank=True)
    object_types = models.JSONField(default=list, blank=True)
    tag_names = models.JSONField(default=list, blank=True)
    owner_ids = models.JSONField(default=list, blank=True)
    expiration_days = models.PositiveIntegerField(blank=True, null=True)
    cooldown_minutes = models.PositiveIntegerField(default=60)
    repeat_minutes = models.PositiveIntegerField(default=1440)
    notify_on_recovery = models.BooleanField(default=False)

    channels = models.ManyToManyField(AlertChannel, related_name="rules", blank=True)
    services = models.ManyToManyField(Service, related_name="alert_rules", blank=True)
    policies = models.ManyToManyField(CertificatePolicy, related_name="alert_rules", blank=True)
    groups = models.ManyToManyField(
        "netbox_certificates.ArtifactGroup",
        related_name="alert_rules",
        blank=True,
    )

    class Meta:
        ordering = ("name",)
        permissions = (
            ("test_alertrule", "Can test alert rules"),
            ("archive_export_alertrule", "Can archive-export alert rules"),
        )

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:alertrule", args=[self.pk])


class AlertEvent(PrimaryModel):
    rule = models.ForeignKey(AlertRule, on_delete=models.SET_NULL, related_name="events", blank=True, null=True)
    channel = models.ForeignKey(AlertChannel, on_delete=models.SET_NULL, related_name="events", blank=True, null=True)
    finding = models.ForeignKey(HealthFinding, on_delete=models.SET_NULL, related_name="alert_events", blank=True, null=True)
    status = models.CharField(max_length=32, choices=AlertEventStatusChoices)
    delivered_at = models.DateTimeField(blank=True, null=True)
    error = models.TextField(blank=True)
    payload_summary = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ("-created",)
        permissions = (
            ("archive_export_alertevent", "Can archive-export alert events"),
        )

    def __str__(self):
        return f"{self.get_status_display()} - {self.created:%Y-%m-%d %H:%M:%S}" if self.created else self.get_status_display()

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:alertevent", args=[self.pk])


# The pre-1.0 CertificateAuthority model remains internal root-identity
# infrastructure. Its old CRUD page/API no longer exists. If legacy code or a
# relationship tries to resolve its URL, send the user to the real CA
# certificate inventory instead of leaving a broken reverse().
def _internal_certificate_authority_absolute_url(self):
    return reverse("plugins:netbox_certificates:certificateauthority_list")


from .models import (
    ArtifactGroup as _ArtifactGroup,
    ArtifactLink as _LegacyArtifactLink,
    CertificateAuthority as _InternalCertificateAuthority,
    ExpiryAlertConfiguration as _LegacyExpiryAlertConfiguration,
    ExpiryAlertEvent as _LegacyExpiryAlertEvent,
)

_InternalCertificateAuthority.get_absolute_url = _internal_certificate_authority_absolute_url

# These pre-1.0 classes/tables are retained only so migrations and established
# certificate-chain internals keep working. They are intentionally not public
# NetBox object types in 1.0.
_InternalCertificateAuthority._netbox_private = True
_LegacyArtifactLink._netbox_private = True
_LegacyExpiryAlertConfiguration._netbox_private = True
_LegacyExpiryAlertEvent._netbox_private = True

# Prevent Django's post_migrate permission creator from reintroducing public CRUD
# permissions for the retained pre-1.0 implementation models. The database
# permission cleanup migration/signal removes historical rows; this stops them
# being synthesized again on subsequent migrate runs.
for _legacy_private_model in (
    _InternalCertificateAuthority,
    _LegacyArtifactLink,
    _LegacyExpiryAlertConfiguration,
    _LegacyExpiryAlertEvent,
):
    _legacy_private_model._meta.default_permissions = ()
    _legacy_private_model._meta.permissions = ()
