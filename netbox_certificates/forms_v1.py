from django import forms
from django.utils.html import format_html_join
from django.utils.safestring import mark_safe
from django.contrib.contenttypes.models import ContentType
from netbox.forms import PrimaryModelBulkEditForm, PrimaryModelFilterSetForm, PrimaryModelForm
from netbox.models import NetBoxModel
from netbox.models.features import model_is_public
from utilities.forms import add_blank_choice
from utilities.forms.fields import DynamicModelChoiceField, DynamicModelMultipleChoiceField
from utilities.forms.rendering import FieldSet

from .choices_v1 import (
    AlertChannelTypeChoices,
    FindingSeverityChoices,
    FindingStatusChoices,
    ServiceCriticalityChoices,
    ServiceEnvironmentChoices,
    ServiceStatusChoices,
    ServiceTypeChoices,
)
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


class DeploymentTextInput(forms.TextInput):
    """HTML datalist-backed text input: suggested presets without a closed enum."""

    presets = (
        "Generic TLS Endpoint",
        "Website",
        "Nginx",
        "Apache HTTP Server",
        "Microsoft IIS",
        "HAProxy",
        "Traefik",
        "Caddy",
        "Kubernetes Ingress",
        "Kubernetes TLS Secret",
        "OpenShift Route",
        "F5 BIG-IP",
        "Citrix ADC",
        "Cloud Load Balancer",
        "API Gateway",
        "Mail Server",
        "Database",
        "VPN Gateway",
        "Repository",
        "Container Registry",
        "Application",
    )

    def __init__(self, attrs=None):
        attrs = dict(attrs or {})
        attrs.setdefault("list", "nbcert-deployment-presets")
        super().__init__(attrs=attrs)

    def render(self, name, value, attrs=None, renderer=None):
        input_html = super().render(name, value, attrs=attrs, renderer=renderer)
        options = format_html_join("", '<option value="{}"></option>', ((value,) for value in self.presets))
        return mark_safe(f'{input_html}<datalist id="nbcert-deployment-presets">{options}</datalist>')


class JSONListField(forms.JSONField):
    def clean(self, value):
        value = super().clean(value)
        if value in (None, ""):
            return []
        if not isinstance(value, list):
            raise forms.ValidationError("Enter a JSON list.")
        return value


class ServiceForm(PrimaryModelForm):
    deployment = forms.CharField(required=True, widget=DeploymentTextInput())
    deployment_metadata = forms.JSONField(required=False)
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False)
    certificates = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False)
    private_keys = DynamicModelMultipleChoiceField(queryset=PrivateKey.objects.all(), required=False)
    csrs = DynamicModelMultipleChoiceField(queryset=CSR.objects.all(), required=False)
    bundles = DynamicModelMultipleChoiceField(queryset=Bundle.objects.all(), required=False)
    policy = DynamicModelChoiceField(queryset=CertificatePolicy.objects.all(), required=False)
    additional_urls = JSONListField(required=False, help_text='JSON list, e.g. ["https://service.example/"]')

    fieldsets = (
        FieldSet("name", "status", "service_type", "other_type", "deployment", "deployment_metadata", "environment", "criticality"),
        FieldSet("protocol", "primary_url", "additional_urls", "hostname", "port", "sni_name", name="Endpoints"),
        FieldSet("external_reference", "contact", "enabled", "policy", name="Management"),
        FieldSet("groups", "certificates", "private_keys", "csrs", "bundles", name="Relationships"),
        FieldSet("owner", "description", "comments", "tags", name="NetBox"),
    )

    class Meta:
        model = Service
        fields = (
            "name", "status", "service_type", "other_type", "deployment", "deployment_metadata", "environment",
            "protocol", "primary_url", "additional_urls", "hostname", "port", "sni_name",
            "criticality", "external_reference", "contact", "enabled", "policy",
            "groups", "certificates", "private_keys", "csrs", "bundles",
            "owner", "description", "comments", "tags",
        )


class ServiceBulkEditForm(PrimaryModelBulkEditForm):
    status = forms.ChoiceField(choices=add_blank_choice(ServiceStatusChoices), required=False)
    service_type = forms.ChoiceField(choices=add_blank_choice(ServiceTypeChoices), required=False)
    other_type = forms.CharField(required=False)
    deployment = forms.CharField(required=False, widget=DeploymentTextInput())
    deployment_metadata = forms.JSONField(required=False)
    environment = forms.ChoiceField(choices=add_blank_choice(ServiceEnvironmentChoices), required=False)
    protocol = forms.CharField(required=False)
    primary_url = forms.URLField(required=False)
    additional_urls = forms.JSONField(required=False)
    port = forms.IntegerField(min_value=1, max_value=65535, required=False)
    sni_name = forms.CharField(required=False)
    hostname = forms.CharField(required=False)
    criticality = forms.ChoiceField(choices=add_blank_choice(ServiceCriticalityChoices), required=False)
    external_reference = forms.CharField(required=False)
    contact = forms.CharField(required=False)
    enabled = forms.NullBooleanField(required=False)
    policy = DynamicModelChoiceField(queryset=CertificatePolicy.objects.all(), required=False)
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False)
    certificates = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False)
    private_keys = DynamicModelMultipleChoiceField(queryset=PrivateKey.objects.all(), required=False)
    csrs = DynamicModelMultipleChoiceField(queryset=CSR.objects.all(), required=False)
    bundles = DynamicModelMultipleChoiceField(queryset=Bundle.objects.all(), required=False)

    model = Service
    fieldsets = (
        FieldSet("status", "service_type", "other_type", "deployment", "deployment_metadata", "environment", "criticality"),
        FieldSet("protocol", "primary_url", "additional_urls", "hostname", "port", "sni_name", name="Endpoints"),
        FieldSet("external_reference", "contact", "enabled", "policy", name="Management"),
        FieldSet("groups", "certificates", "private_keys", "csrs", "bundles", name="Relationships"),
        FieldSet("description", name="NetBox"),
    )
    nullable_fields = (
        "other_type", "primary_url", "additional_urls", "hostname", "sni_name", "external_reference", "contact", "policy",
        "description", "comments",
    )


class ServiceFilterForm(PrimaryModelFilterSetForm):
    model = Service
    q = forms.CharField(required=False, label="Search")
    status = forms.MultipleChoiceField(choices=ServiceStatusChoices, required=False)
    service_type = forms.MultipleChoiceField(choices=ServiceTypeChoices, required=False)
    deployment = forms.CharField(required=False)
    deployment_metadata = forms.CharField(required=False, help_text="JSON object containment filter")
    environment = forms.MultipleChoiceField(choices=ServiceEnvironmentChoices, required=False)
    criticality = forms.MultipleChoiceField(choices=ServiceCriticalityChoices, required=False)
    protocol = forms.CharField(required=False)
    primary_url = forms.CharField(required=False)
    additional_url = forms.CharField(required=False)
    hostname = forms.CharField(required=False)
    port = forms.IntegerField(required=False)
    sni_name = forms.CharField(required=False)
    external_reference = forms.CharField(required=False)
    contact = forms.CharField(required=False)
    enabled = forms.NullBooleanField(required=False)
    groups_id = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False)
    certificate_id = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False)
    private_key_id = DynamicModelMultipleChoiceField(queryset=PrivateKey.objects.all(), required=False)
    csr_id = DynamicModelMultipleChoiceField(queryset=CSR.objects.all(), required=False)
    bundle_id = DynamicModelMultipleChoiceField(queryset=Bundle.objects.all(), required=False)
    policy_id = DynamicModelMultipleChoiceField(queryset=CertificatePolicy.objects.all(), required=False)

    fieldsets = (
        FieldSet("q"),
        FieldSet("status", "service_type", "deployment", "deployment_metadata", "environment", "criticality", "enabled"),
        FieldSet("protocol", "primary_url", "additional_url", "hostname", "port", "sni_name", name="Endpoints"),
        FieldSet("external_reference", "contact", name="Management"),
        FieldSet("groups_id", "certificate_id", "private_key_id", "csr_id", "bundle_id", "policy_id", name="Relationships"),
    )


class CertificatePolicyForm(PrimaryModelForm):
    allowed_key_types = JSONListField(required=False)
    allowed_signature_algorithms = JSONListField(required=False)
    allowed_curves = JSONListField(required=False)
    allowed_issuers = JSONListField(required=False)
    certificates = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False)
    csrs = DynamicModelMultipleChoiceField(queryset=CSR.objects.all(), required=False)
    bundles = DynamicModelMultipleChoiceField(queryset=Bundle.objects.all(), required=False)

    class Meta:
        model = CertificatePolicy
        fields = (
            "name", "enabled", "minimum_rsa_bits", "allowed_key_types", "allowed_signature_algorithms",
            "allowed_curves", "max_validity_days", "require_san", "allow_wildcards", "allow_ca",
            "allowed_issuers", "forbid_key_reuse", "certificates", "csrs", "bundles",
            "owner", "description", "comments", "tags",
        )


class CertificatePolicyBulkEditForm(PrimaryModelBulkEditForm):
    enabled = forms.NullBooleanField(required=False)
    minimum_rsa_bits = forms.IntegerField(min_value=1024, required=False)
    allowed_key_types = forms.JSONField(required=False)
    allowed_signature_algorithms = forms.JSONField(required=False)
    allowed_curves = forms.JSONField(required=False)
    max_validity_days = forms.IntegerField(min_value=1, required=False)
    allowed_issuers = forms.JSONField(required=False)
    certificates = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False)
    csrs = DynamicModelMultipleChoiceField(queryset=CSR.objects.all(), required=False)
    bundles = DynamicModelMultipleChoiceField(queryset=Bundle.objects.all(), required=False)
    require_san = forms.NullBooleanField(required=False)
    allow_wildcards = forms.NullBooleanField(required=False)
    allow_ca = forms.NullBooleanField(required=False)
    forbid_key_reuse = forms.NullBooleanField(required=False)

    model = CertificatePolicy
    fieldsets = (
        FieldSet(
            "enabled", "minimum_rsa_bits", "allowed_key_types", "allowed_signature_algorithms",
            "allowed_curves", "max_validity_days", "allowed_issuers", "require_san",
            "allow_wildcards", "allow_ca", "forbid_key_reuse", "certificates", "csrs", "bundles", "description"
        ),
    )
    nullable_fields = ("max_validity_days", "description", "comments")


class CertificatePolicyFilterForm(PrimaryModelFilterSetForm):
    model = CertificatePolicy
    q = forms.CharField(required=False)
    enabled = forms.NullBooleanField(required=False)
    minimum_rsa_bits = forms.IntegerField(required=False)
    allowed_key_types = forms.CharField(required=False)
    allowed_signature_algorithms = forms.CharField(required=False)
    allowed_curves = forms.CharField(required=False)
    max_validity_days = forms.IntegerField(required=False)
    require_san = forms.NullBooleanField(required=False)
    allow_wildcards = forms.NullBooleanField(required=False)
    allow_ca = forms.NullBooleanField(required=False)
    allowed_issuers = forms.CharField(required=False)
    forbid_key_reuse = forms.NullBooleanField(required=False)
    certificate_id = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False)
    csr_id = DynamicModelMultipleChoiceField(queryset=CSR.objects.all(), required=False)
    bundle_id = DynamicModelMultipleChoiceField(queryset=Bundle.objects.all(), required=False)

    fieldsets = (
        FieldSet("q"),
        FieldSet(
            "enabled", "minimum_rsa_bits", "allowed_key_types", "allowed_signature_algorithms",
            "allowed_curves", "max_validity_days", "require_san", "allow_wildcards",
            "allow_ca", "allowed_issuers", "forbid_key_reuse",
        ),
        FieldSet("certificate_id", "csr_id", "bundle_id", name="Assignments"),
    )


class HealthFindingBulkEditForm(PrimaryModelBulkEditForm):
    # Health evidence/severity is generated by the analysis engine. Operators can
    # manage workflow state and NetBox metadata, but cannot falsify the finding.
    status = forms.ChoiceField(choices=add_blank_choice(FindingStatusChoices), required=False)

    model = HealthFinding
    fieldsets = (FieldSet("status", "description"),)
    nullable_fields = ("description", "comments")


class HealthFindingFilterForm(PrimaryModelFilterSetForm):
    model = HealthFinding
    q = forms.CharField(required=False)
    code = forms.CharField(required=False)
    category = forms.CharField(required=False)
    severity = forms.MultipleChoiceField(choices=FindingSeverityChoices, required=False)
    status = forms.MultipleChoiceField(choices=FindingStatusChoices, required=False)
    object_type_id = forms.ModelMultipleChoiceField(queryset=ContentType.objects.all(), required=False)
    related_type_id = forms.ModelMultipleChoiceField(queryset=ContentType.objects.all(), required=False)
    object_id = forms.IntegerField(required=False)
    related_object_id = forms.IntegerField(required=False)
    details = forms.CharField(required=False)
    evidence = forms.CharField(required=False)


class ObjectLinkForm(PrimaryModelForm):
    source_type = forms.ModelChoiceField(queryset=ContentType.objects.none())
    target_type = forms.ModelChoiceField(queryset=ContentType.objects.none())

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        public_ids = []
        for content_type in ContentType.objects.all():
            model = content_type.model_class()
            if (
                model is not None
                and isinstance(model, type)
                and issubclass(model, NetBoxModel)
                and model_is_public(model)
            ):
                public_ids.append(content_type.pk)
        queryset = ContentType.objects.filter(pk__in=public_ids).order_by("app_label", "model")
        self.fields["source_type"].queryset = queryset
        self.fields["target_type"].queryset = queryset

    class Meta:
        model = ObjectLink
        fields = (
            "source_type", "source_object_id", "target_type", "target_object_id",
            "relationship", "label", "enabled", "owner", "description", "comments", "tags",
        )


class ObjectLinkBulkEditForm(PrimaryModelBulkEditForm):
    relationship = forms.CharField(required=False)
    label = forms.CharField(required=False)
    enabled = forms.NullBooleanField(required=False)

    model = ObjectLink
    fieldsets = (FieldSet("relationship", "label", "enabled", "description"),)
    nullable_fields = ("label", "description", "comments")


class ObjectLinkFilterForm(PrimaryModelFilterSetForm):
    model = ObjectLink
    q = forms.CharField(required=False)
    automatic = forms.NullBooleanField(required=False)
    source_type_id = forms.ModelMultipleChoiceField(queryset=ContentType.objects.all(), required=False)
    source_object_id = forms.IntegerField(required=False)
    target_type_id = forms.ModelMultipleChoiceField(queryset=ContentType.objects.all(), required=False)
    target_object_id = forms.IntegerField(required=False)
    relationship = forms.CharField(required=False)
    label = forms.CharField(required=False)
    enabled = forms.NullBooleanField(required=False)


class AlertChannelForm(PrimaryModelForm):
    recipients = JSONListField(required=False)
    smtp_password = forms.CharField(
        required=False,
        widget=forms.PasswordInput(render_value=False),
        help_text="Leave blank while editing to preserve the existing encrypted password.",
    )
    webhook_url = forms.URLField(required=False)
    webhook_headers = forms.JSONField(required=False)

    fieldsets = (
        FieldSet("name", "enabled", "channel_type", "recipients", "subject_prefix"),
        FieldSet(
            "smtp_host", "smtp_port", "smtp_username", "smtp_password",
            "smtp_use_tls", "smtp_use_ssl", "from_email",
            name="SMTP",
        ),
        FieldSet("webhook_url", "webhook_headers", name="Webhook"),
        FieldSet("owner", "description", "comments", "tags", name="NetBox"),
    )

    class Meta:
        model = AlertChannel
        fields = (
            "name", "enabled", "channel_type", "recipients",
            "smtp_host", "smtp_port", "smtp_username", "smtp_password",
            "smtp_use_tls", "smtp_use_ssl", "from_email",
            "webhook_url", "webhook_headers", "subject_prefix",
            "owner", "description", "comments", "tags",
        )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance and self.instance.pk:
            from .services.secret_v1 import decrypt_json, decrypt_text
            self.fields["webhook_url"].initial = decrypt_text(self.instance.webhook_url_encrypted, default="")
            self.fields["webhook_headers"].initial = decrypt_json(self.instance.webhook_headers_encrypted)

    def clean(self):
        cleaned = super().clean()
        if cleaned.get("channel_type") == AlertChannelTypeChoices.WEBHOOK and not cleaned.get("webhook_url"):
            self.add_error("webhook_url", "Webhook URL is required for a webhook channel.")
        if cleaned.get("channel_type") == AlertChannelTypeChoices.EMAIL:
            if not cleaned.get("recipients"):
                self.add_error("recipients", "At least one recipient is required for an email channel.")
            if not cleaned.get("smtp_host"):
                self.add_error("smtp_host", "SMTP host is required for an email channel.")
            if cleaned.get("smtp_use_tls") and cleaned.get("smtp_use_ssl"):
                self.add_error("smtp_use_ssl", "TLS and SSL cannot both be enabled.")
        return cleaned

    def save(self, commit=True):
        from .services.secret_v1 import encrypt_json, encrypt_text
        instance = super().save(commit=False)
        submitted_password = self.cleaned_data.get("smtp_password", "")
        if submitted_password:
            instance.smtp_password_encrypted = encrypt_text(submitted_password)
        instance.webhook_url_encrypted = encrypt_text(self.cleaned_data.get("webhook_url", ""))
        instance.webhook_headers_encrypted = encrypt_json(self.cleaned_data.get("webhook_headers") or {})
        if commit:
            instance.save()
            self.save_m2m()
        return instance


class AlertChannelBulkEditForm(PrimaryModelBulkEditForm):
    enabled = forms.NullBooleanField(required=False)
    subject_prefix = forms.CharField(required=False)
    recipients = forms.JSONField(required=False)
    smtp_host = forms.CharField(required=False)
    smtp_port = forms.IntegerField(min_value=1, max_value=65535, required=False)
    smtp_username = forms.CharField(required=False)
    smtp_use_tls = forms.NullBooleanField(required=False)
    smtp_use_ssl = forms.NullBooleanField(required=False)
    from_email = forms.EmailField(required=False)

    model = AlertChannel
    fieldsets = (
        FieldSet("enabled", "subject_prefix"),
        FieldSet("recipients", "smtp_host", "smtp_port", "smtp_username", "smtp_use_tls", "smtp_use_ssl", "from_email", name="SMTP"),
        FieldSet("description"),
    )
    nullable_fields = ("description", "comments")


class AlertChannelFilterForm(PrimaryModelFilterSetForm):
    model = AlertChannel
    q = forms.CharField(required=False)
    enabled = forms.NullBooleanField(required=False)
    channel_type = forms.MultipleChoiceField(choices=AlertChannelTypeChoices, required=False)
    recipients = forms.CharField(required=False)
    smtp_host = forms.CharField(required=False)
    smtp_port = forms.IntegerField(required=False)
    smtp_username = forms.CharField(required=False)
    smtp_use_tls = forms.NullBooleanField(required=False)
    smtp_use_ssl = forms.NullBooleanField(required=False)
    from_email = forms.CharField(required=False)
    subject_prefix = forms.CharField(required=False)


class AlertRuleForm(PrimaryModelForm):
    finding_codes = JSONListField(required=False)
    categories = JSONListField(required=False)
    severities = JSONListField(required=False)
    statuses = JSONListField(required=False)
    object_types = JSONListField(required=False, help_text='Optional object labels, e.g. ["netbox_certificates.certificate"].')
    tag_names = JSONListField(required=False)
    owner_ids = JSONListField(required=False)
    channels = DynamicModelMultipleChoiceField(queryset=AlertChannel.objects.all(), required=False)
    services = DynamicModelMultipleChoiceField(queryset=Service.objects.all(), required=False)
    policies = DynamicModelMultipleChoiceField(queryset=CertificatePolicy.objects.all(), required=False)
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False)

    class Meta:
        model = AlertRule
        fields = (
            "name", "enabled", "finding_codes", "categories", "severities", "statuses",
            "object_types", "tag_names", "owner_ids", "expiration_days",
            "cooldown_minutes", "repeat_minutes", "notify_on_recovery",
            "channels", "services", "policies", "groups", "owner", "description", "comments", "tags",
        )


class AlertRuleBulkEditForm(PrimaryModelBulkEditForm):
    enabled = forms.NullBooleanField(required=False)
    finding_codes = forms.JSONField(required=False)
    categories = forms.JSONField(required=False)
    severities = forms.JSONField(required=False)
    statuses = forms.JSONField(required=False)
    object_types = forms.JSONField(required=False)
    tag_names = forms.JSONField(required=False)
    owner_ids = forms.JSONField(required=False)
    cooldown_minutes = forms.IntegerField(min_value=0, required=False)
    repeat_minutes = forms.IntegerField(min_value=0, required=False)
    notify_on_recovery = forms.NullBooleanField(required=False)
    expiration_days = forms.IntegerField(min_value=1, required=False)
    channels = DynamicModelMultipleChoiceField(queryset=AlertChannel.objects.all(), required=False)
    services = DynamicModelMultipleChoiceField(queryset=Service.objects.all(), required=False)
    policies = DynamicModelMultipleChoiceField(queryset=CertificatePolicy.objects.all(), required=False)
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False)

    model = AlertRule
    fieldsets = (
        FieldSet("enabled", "finding_codes", "categories", "severities", "statuses", "object_types", "tag_names", "owner_ids", name="Finding Scope"),
        FieldSet("expiration_days", "cooldown_minutes", "repeat_minutes", "notify_on_recovery", name="Timing"),
        FieldSet("channels", "services", "policies", "groups", name="Scope"),
        FieldSet("description"),
    )
    nullable_fields = ("description", "comments")


class AlertRuleFilterForm(PrimaryModelFilterSetForm):
    model = AlertRule
    q = forms.CharField(required=False)
    enabled = forms.NullBooleanField(required=False)
    finding_codes = forms.CharField(required=False)
    categories = forms.CharField(required=False)
    severities = forms.CharField(required=False)
    statuses = forms.CharField(required=False)
    object_types = forms.CharField(required=False)
    tag_names = forms.CharField(required=False)
    owner_ids = forms.CharField(required=False)
    expiration_days = forms.IntegerField(required=False)
    cooldown_minutes = forms.IntegerField(required=False)
    repeat_minutes = forms.IntegerField(required=False)
    notify_on_recovery = forms.NullBooleanField(required=False)
    channel_id = DynamicModelMultipleChoiceField(queryset=AlertChannel.objects.all(), required=False)
    service_id = DynamicModelMultipleChoiceField(queryset=Service.objects.all(), required=False)
    policy_id = DynamicModelMultipleChoiceField(queryset=CertificatePolicy.objects.all(), required=False)
    group_id = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False)


class AlertEventBulkEditForm(PrimaryModelBulkEditForm):
    model = AlertEvent
    fieldsets = (FieldSet("description"),)
    nullable_fields = ("description", "comments")


class AlertEventFilterForm(PrimaryModelFilterSetForm):
    model = AlertEvent
    q = forms.CharField(required=False)
    status = forms.CharField(required=False)
    error = forms.CharField(required=False)
    payload_summary = forms.CharField(required=False, help_text="JSON object containment filter")
    rule_id = DynamicModelMultipleChoiceField(queryset=AlertRule.objects.all(), required=False)
    channel_id = DynamicModelMultipleChoiceField(queryset=AlertChannel.objects.all(), required=False)
    finding_id = DynamicModelMultipleChoiceField(queryset=HealthFinding.objects.all(), required=False)
