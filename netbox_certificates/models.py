from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import models
from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.urls import reverse
from django.utils.translation import gettext_lazy as _
from netbox.models import NetBoxModel, PrimaryModel

from .choices import (
    AlertMethodChoices,
    AlertRepeatModeChoices,
    AlertTriggerUnitChoices,
    BundleFormatChoices,
    BundleStatusChoices,
    CertificateStatusChoices,
    LinkOriginChoices,
    LinkRelationChoices,
    SourceFormatChoices,
)


class ArtifactGroup(PrimaryModel):
    """Hierarchical user-managed group for certificate objects and Bundles."""

    name = models.CharField(max_length=200, unique=True)
    parent = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="children",
        verbose_name="parent group",
    )

    class Meta:
        ordering = ("name",)
        verbose_name = "group"
        verbose_name_plural = "groups"

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:artifactgroup", args=[self.pk])

    def ancestor_ids(self):
        """Return ancestor primary keys, protecting against malformed legacy loops."""
        result = []
        current = self.parent
        visited = set()
        while current is not None and current.pk not in visited:
            visited.add(current.pk)
            result.append(current.pk)
            current = current.parent
        return result

    def descendant_ids(self):
        """Return descendant primary keys for hierarchy validation and UI filtering."""
        if not self.pk:
            return []
        found = set()
        pending = [self.pk]
        while pending:
            parent_id = pending.pop()
            child_ids = list(
                ArtifactGroup.objects.filter(parent_id=parent_id)
                .exclude(pk__in=found)
                .values_list("pk", flat=True)
            )
            for child_id in child_ids:
                if child_id not in found:
                    found.add(child_id)
                    pending.append(child_id)
        found.discard(self.pk)
        return sorted(found)

    def clean(self):
        super().clean()
        if self.parent_id is None:
            return
        if self.pk and self.parent_id == self.pk:
            raise ValidationError({"parent": "A group cannot be its own parent."})
        if self.pk and self.parent_id in set(self.descendant_ids()):
            raise ValidationError({"parent": "A group cannot be nested below one of its descendants."})


class CertificateAuthority(PrimaryModel):
    """Root CA identity derived from stored self-signed root certificates."""

    name = models.CharField(max_length=255, db_index=True)
    issuer_dn = models.TextField(unique=True, editable=False)

    class Meta:
        ordering = ("name", "pk")
        verbose_name = "certificate authority"
        verbose_name_plural = "certificate authorities"

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:certificateauthority", args=[self.pk])


class Certificate(PrimaryModel):
    name = models.CharField(max_length=200)
    status = models.CharField(max_length=32, choices=CertificateStatusChoices, default=CertificateStatusChoices.INVALID)
    source_filename = models.CharField(max_length=255, blank=True)
    source_format = models.CharField(max_length=32, choices=SourceFormatChoices, default=SourceFormatChoices.PEM)
    material = models.TextField(verbose_name=_("certificate material"))
    fingerprint_sha256 = models.CharField(max_length=64, unique=True, editable=False)
    public_key_fingerprint = models.CharField(max_length=64, db_index=True, editable=False)
    serial_number = models.CharField(max_length=128, blank=True, editable=False)
    subject = models.TextField(blank=True, editable=False)
    issuer = models.TextField(blank=True, editable=False)
    authority = models.ForeignKey(
        CertificateAuthority,
        on_delete=models.SET_NULL,
        blank=True,
        null=True,
        related_name="certificates",
        editable=False,
    )
    subject_alternative_names = models.JSONField(default=list, blank=True, editable=False)
    valid_from = models.DateTimeField(blank=True, null=True, editable=False)
    valid_to = models.DateTimeField(blank=True, null=True, editable=False)
    signature_algorithm = models.CharField(max_length=128, blank=True, editable=False)
    key_type = models.CharField(max_length=32, blank=True, editable=False)
    key_size = models.PositiveIntegerField(blank=True, null=True, editable=False)
    curve = models.CharField(max_length=64, blank=True, editable=False)
    is_ca = models.BooleanField(default=False, editable=False)
    parent_certificate = models.ForeignKey(
        "self", on_delete=models.SET_NULL, blank=True, null=True, related_name="issued_certificates"
    )
    supersedes = models.ForeignKey(
        "self", on_delete=models.SET_NULL, blank=True, null=True, related_name="superseded_by"
    )
    trigger_unit = models.CharField(
        max_length=16, choices=AlertTriggerUnitChoices, blank=True, verbose_name="Trigger Unit"
    )
    alert_trigger = models.PositiveIntegerField(blank=True, null=True, verbose_name="Alert Trigger")
    groups = models.ManyToManyField(ArtifactGroup, blank=True, related_name="certificates")

    class Meta:
        ordering = ("name", "valid_to")
        verbose_name = "certificate"
        verbose_name_plural = "certificates"
        permissions = (("download_certificate", "Can download certificate material"),)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:certificate", args=[self.pk])

    def clean(self):
        super().clean()
        has_unit = bool(self.trigger_unit)
        has_trigger = self.alert_trigger is not None
        if has_unit != has_trigger:
            raise ValidationError("Alert Trigger and Trigger Unit must be configured together.")
        if self.alert_trigger is not None and self.alert_trigger <= 0:
            raise ValidationError({"alert_trigger": "Alert Trigger must be greater than zero."})


class PrivateKey(PrimaryModel):
    name = models.CharField(max_length=200)
    source_filename = models.CharField(max_length=255, blank=True)
    source_format = models.CharField(max_length=32, choices=SourceFormatChoices, default=SourceFormatChoices.PEM)
    encrypted_material = models.BinaryField(editable=False)
    material_sha256 = models.CharField(max_length=64, editable=False)
    public_key_fingerprint = models.CharField(max_length=64, unique=True, editable=False)
    key_type = models.CharField(max_length=32, blank=True, editable=False)
    key_size = models.PositiveIntegerField(blank=True, null=True, editable=False)
    encrypted_on_import = models.BooleanField(default=False, editable=False)
    groups = models.ManyToManyField(ArtifactGroup, blank=True, related_name="private_keys")

    class Meta:
        ordering = ("name",)
        verbose_name = "private key"
        verbose_name_plural = "private keys"
        permissions = (("download_privatekey", "Can download private key material"),)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:privatekey", args=[self.pk])


class CSR(PrimaryModel):
    name = models.CharField(max_length=200)
    source_filename = models.CharField(max_length=255, blank=True)
    source_format = models.CharField(max_length=32, choices=SourceFormatChoices, default=SourceFormatChoices.PEM)
    material = models.TextField(verbose_name=_("CSR material"))
    fingerprint_sha256 = models.CharField(max_length=64, unique=True, editable=False)
    public_key_fingerprint = models.CharField(max_length=64, db_index=True, editable=False)
    subject = models.TextField(blank=True, editable=False)
    subject_alternative_names = models.JSONField(default=list, blank=True, editable=False)
    signature_algorithm = models.CharField(max_length=128, blank=True, editable=False)
    key_type = models.CharField(max_length=32, blank=True, editable=False)
    key_size = models.PositiveIntegerField(blank=True, null=True, editable=False)
    curve = models.CharField(max_length=64, blank=True, editable=False)
    groups = models.ManyToManyField(ArtifactGroup, blank=True, related_name="csrs")

    class Meta:
        ordering = ("name",)
        verbose_name = "CSR"
        verbose_name_plural = "CSRs"
        permissions = (("download_csr", "Can download CSR material"),)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:csr", args=[self.pk])


class Bundle(PrimaryModel):
    name = models.CharField(max_length=200)
    identity_fingerprint = models.CharField(
        max_length=64, blank=True, null=True, unique=True, editable=False, db_index=True
    )
    source_filename = models.CharField(max_length=255, blank=True)
    archive_format = models.CharField(max_length=32, choices=BundleFormatChoices, default=BundleFormatChoices.ZIP)
    status = models.CharField(max_length=32, choices=BundleStatusChoices, default=BundleStatusChoices.PARTIAL)
    encrypted_archive = models.BinaryField(blank=True, null=True, editable=False)
    import_report = models.JSONField(default=dict, blank=True, editable=False)
    certificate = models.ForeignKey(
        Certificate, on_delete=models.SET_NULL, blank=True, null=True, related_name="primary_in_bundles"
    )
    private_key = models.ForeignKey(
        PrivateKey, on_delete=models.SET_NULL, blank=True, null=True, related_name="bundles"
    )
    csr = models.ForeignKey(CSR, on_delete=models.SET_NULL, blank=True, null=True, related_name="bundles")
    chain_certificates = models.ManyToManyField(Certificate, blank=True, related_name="chain_in_bundles")
    groups = models.ManyToManyField(ArtifactGroup, blank=True, related_name="bundles")

    class Meta:
        ordering = ("name",)
        verbose_name = "bundle"
        verbose_name_plural = "bundles"
        permissions = (
            ("export_bundle", "Can export bundle material"),
            ("export_pfx_bundle", "Can export bundle as PKCS#12/PFX"),
        )

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:netbox_certificates:bundle", args=[self.pk])


class ArtifactLink(NetBoxModel):
    source_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="netbox_certificate_source_links")
    source_id = models.PositiveBigIntegerField()
    source_object = GenericForeignKey("source_type", "source_id")
    target_type = models.ForeignKey(ContentType, on_delete=models.CASCADE, related_name="netbox_certificate_target_links")
    target_id = models.PositiveBigIntegerField()
    target_object = GenericForeignKey("target_type", "target_id")
    relation = models.CharField(max_length=32, choices=LinkRelationChoices, default=LinkRelationChoices.RELATED)
    origin = models.CharField(max_length=32, choices=LinkOriginChoices, default=LinkOriginChoices.MANUAL)
    active = models.BooleanField(default=True)
    note = models.CharField(max_length=255, blank=True)

    class Meta:
        ordering = ("source_type", "source_id", "relation")
        constraints = (
            models.UniqueConstraint(
                fields=("source_type", "source_id", "target_type", "target_id", "relation"),
                name="netbox_certificates_unique_artifact_link",
            ),
        )

    def __str__(self):
        return f"{self.source_object} -> {self.target_object} ({self.get_relation_display()})"

    @classmethod
    def for_object(cls, obj):
        ct = ContentType.objects.get_for_model(obj, for_concrete_model=False)
        return cls.objects.filter(
            models.Q(source_type=ct, source_id=obj.pk) | models.Q(target_type=ct, target_id=obj.pk),
            active=True,
        )


class ExpiryAlertConfiguration(NetBoxModel):
    """Singleton configuration for certificate-expiry notifications."""

    check_interval_minutes = models.PositiveIntegerField(default=60)
    alert_on_expired_certificates = models.BooleanField(
        default=True,
        verbose_name="Alert on already expired certificates",
        help_text=(
            "When enabled, certificates that are already expired remain eligible for an alert "
            "if their configured trigger is due."
        ),
    )
    alert_repeat_mode = models.CharField(
        max_length=16,
        choices=AlertRepeatModeChoices,
        default=AlertRepeatModeChoices.ONCE,
        verbose_name="Alert repeat behavior",
        help_text=(
            "Send once per certificate validity/trigger/method, or repeat on every configured check "
            "while the certificate remains due."
        ),
    )

    email_enabled = models.BooleanField(default=False)
    smtp_host = models.CharField(max_length=255, blank=True, verbose_name="SMTP host")
    smtp_port = models.PositiveIntegerField(default=587, verbose_name="SMTP port")
    smtp_username = models.CharField(max_length=255, blank=True, verbose_name="SMTP username")
    smtp_password_encrypted = models.BinaryField(blank=True, null=True, editable=False)
    smtp_use_tls = models.BooleanField(default=True, verbose_name="Use STARTTLS")
    smtp_use_ssl = models.BooleanField(default=False, verbose_name="Use implicit SSL/TLS")
    email_from_address = models.EmailField(blank=True, verbose_name="From address")
    email_recipients = models.TextField(blank=True, verbose_name="Recipients")
    include_superusers = models.BooleanField(default=True, verbose_name="Include active NetBox superusers")

    webhook_enabled = models.BooleanField(default=False, verbose_name="Enable webhook")
    webhook_url_encrypted = models.BinaryField(blank=True, null=True, editable=False)
    webhook_bearer_token_encrypted = models.BinaryField(blank=True, null=True, editable=False)
    webhook_allow_http = models.BooleanField(default=False, verbose_name="Allow insecure HTTP webhook")
    webhook_ignore_tls_verification = models.BooleanField(
        default=False,
        verbose_name="Ignore TLS certificate verification",
        help_text="Disable HTTPS certificate and hostname verification for webhook connections. Use only for trusted internal endpoints.",
    )

    last_check_at = models.DateTimeField(blank=True, null=True, editable=False)
    last_check_success = models.BooleanField(blank=True, null=True, editable=False)
    last_check_message = models.CharField(max_length=500, blank=True, editable=False)
    email_last_test_at = models.DateTimeField(blank=True, null=True, editable=False)
    email_last_test_success = models.BooleanField(blank=True, null=True, editable=False)
    email_last_test_message = models.CharField(max_length=500, blank=True, editable=False)
    webhook_last_test_at = models.DateTimeField(blank=True, null=True, editable=False)
    webhook_last_test_success = models.BooleanField(blank=True, null=True, editable=False)
    webhook_last_test_message = models.CharField(max_length=500, blank=True, editable=False)

    class Meta:
        verbose_name = "expiration alert configuration"
        verbose_name_plural = "expiration alert configuration"
        default_permissions = ("add", "change", "view")
        permissions = (("test_expiryalertconfiguration", "Can test expiration alert configuration"),)

    def __str__(self):
        return "Expiration Alerts"

    def save(self, *args, **kwargs):
        if self.pk is None and self.__class__.objects.exists():
            raise ValidationError("Only one expiration alert configuration can exist.")
        return super().save(*args, **kwargs)


class ExpiryAlertEvent(NetBoxModel):
    certificate = models.ForeignKey(Certificate, on_delete=models.CASCADE, related_name="expiry_alert_events")
    method = models.CharField(max_length=16, choices=AlertMethodChoices)
    certificate_valid_to = models.DateTimeField()
    trigger_unit = models.CharField(max_length=16, choices=AlertTriggerUnitChoices)
    alert_trigger = models.PositiveIntegerField()
    trigger_at = models.DateTimeField()
    last_attempt_at = models.DateTimeField(blank=True, null=True, editable=False)
    delivered_at = models.DateTimeField(blank=True, null=True, editable=False)
    success = models.BooleanField(default=False, editable=False)
    attempt_count = models.PositiveIntegerField(default=0, editable=False)
    status_code = models.PositiveIntegerField(blank=True, null=True, editable=False)
    message = models.CharField(max_length=500, blank=True, editable=False)

    class Meta:
        ordering = ("-last_attempt_at", "-created")
        verbose_name = "expiration alert event"
        verbose_name_plural = "expiration alert events"
        default_permissions = ("view", "delete")
        constraints = (
            models.UniqueConstraint(
                fields=("certificate", "method", "certificate_valid_to", "trigger_unit", "alert_trigger"),
                name="netbox_certificates_unique_expiry_alert_event",
            ),
        )

    def __str__(self):
        return f"{self.certificate} / {self.get_method_display()} / {self.certificate_valid_to}"


def delete_empty_bundles():
    empty_bundles = (
        Bundle.objects.filter(
            certificate__isnull=True,
            private_key__isnull=True,
            csr__isnull=True,
            chain_certificates__isnull=True,
        )
        .distinct()
    )
    for bundle in empty_bundles:
        bundle.delete()


@receiver(post_delete, sender=Certificate)
@receiver(post_delete, sender=PrivateKey)
@receiver(post_delete, sender=CSR)
def cleanup_empty_bundles_after_member_delete(sender, instance, **kwargs):
    delete_empty_bundles()

# Public 1.0 management models. Imported after the established cryptographic
# model classes to preserve their implementation and avoid circular initialization.
from .models_v1 import (
    AlertChannel,
    AlertEvent,
    AlertRule,
    CertificatePolicy,
    HealthFinding,
    ObjectLink,
    Service,
)
