"""A single configuration screen backed by the existing delivery engine."""
import uuid

from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.shortcuts import redirect, render
from django.views import View

from .labels import AcronymFormMixin
from .choices_v1 import FindingSeverityChoices
from .forms_v1 import LineListField
from .models_v1 import AlertChannel, AlertEvent, AlertRule, AlertSettings
from .services.secret_v1 import SecretConfigurationError, encrypt_text, encrypt_json


class AlertSettingsForm(AcronymFormMixin, forms.Form):
    enabled = forms.BooleanField(required=False, label="Enable certificate alerts")
    categories = forms.MultipleChoiceField(required=True, choices=[
        ("validity", "Expiration and validity"), ("chain", "Certificate chain"),
        ("security", "Cryptographic weaknesses"), ("relationship", "Artifact relationships"),
        ("duplicate", "Duplicate material"), ("service", "Service configuration"),
        ("policy", "Policy violations"),
    ], initial=["validity", "chain", "security", "relationship", "duplicate", "service", "policy"])
    severities = forms.MultipleChoiceField(required=False, choices=FindingSeverityChoices,
                                         help_text="Leave empty to include every severity.")
    cooldown_minutes = forms.IntegerField(min_value=15, initial=60, label="Minimum minutes between alerts")
    repeat_minutes = forms.IntegerField(min_value=0, initial=1440, label="Repeat unresolved alerts after minutes",
                                       help_text="0 sends once per occurrence. Delivery runs on NetBox's 15-minute job cycle.")
    notify_on_recovery = forms.BooleanField(required=False, label="Notify when a problem is resolved")
    email_enabled = forms.BooleanField(required=False, label="Enable email alerts")
    recipients = LineListField(required=False, widget=forms.Textarea(attrs={"rows": 3}), help_text="One email address per line.")
    smtp_host = forms.CharField(required=False, max_length=255)
    smtp_port = forms.IntegerField(min_value=1, max_value=65535, initial=587, required=False)
    smtp_username = forms.CharField(required=False, max_length=255)
    smtp_password = forms.CharField(required=False, strip=False, widget=forms.PasswordInput(render_value=False),
                                    help_text="Leave blank to keep the saved password.")
    clear_smtp_password = forms.BooleanField(required=False, label="Clear saved SMTP password")
    smtp_security = forms.ChoiceField(initial="starttls", choices=[("starttls", "STARTTLS"), ("ssl", "Implicit TLS / SSL"), ("none", "No TLS")])
    smtp_verify_tls = forms.BooleanField(required=False, initial=True, label="Verify SMTP TLS certificate",
                                       help_text="Turn off to allow self-signed or otherwise untrusted SMTP certificates.")
    from_email = forms.EmailField(required=False)
    subject_prefix = forms.CharField(initial="[NetBox Certificates]", max_length=120)
    webhook_enabled = forms.BooleanField(required=False, label="Enable webhook alerts")
    webhook_url = forms.URLField(required=False, assume_scheme="https", widget=forms.PasswordInput(render_value=False),
                                help_text="Leave blank to keep the saved URL.")
    webhook_headers = forms.JSONField(required=False, widget=forms.Textarea(attrs={"rows": 3}),
                                     help_text="Optional JSON object. Leave blank to keep saved headers; {} clears them.")
    webhook_verify_tls = forms.BooleanField(required=False, initial=True, label="Verify webhook TLS certificate",
                                          help_text="Turn off to allow self-signed or otherwise untrusted HTTPS certificates.")

    def __init__(self, *args, config=None, test_method=None, **kwargs):
        self.config = config
        self.test_method = test_method
        initial = {}
        if config:
            rule, email, webhook = config.rule, config.email_channel, config.webhook_channel
            if rule:
                for field in ("enabled", "categories", "severities", "cooldown_minutes", "repeat_minutes", "notify_on_recovery"):
                    initial[field] = getattr(rule, field)
            if email:
                for field in ("recipients", "smtp_host", "smtp_port", "smtp_username", "smtp_verify_tls", "from_email", "subject_prefix"):
                    initial[field] = getattr(email, field)
                initial["email_enabled"] = email.enabled
                initial["smtp_security"] = "starttls" if email.smtp_use_tls else "ssl" if email.smtp_use_ssl else "none"
            if webhook:
                initial["webhook_enabled"] = webhook.enabled
                initial["webhook_verify_tls"] = webhook.webhook_verify_tls
        kwargs["initial"] = initial
        super().__init__(*args, **kwargs)

    def clean(self):
        data = super().clean()
        for address in data.get("recipients", []):
            try:
                validate_email(address)
            except forms.ValidationError:
                self.add_error("recipients", f"Invalid email address: {address}")
        if data.get("email_enabled") or self.test_method == "email":
            for field in ("recipients", "smtp_host", "smtp_port", "from_email"):
                if not data.get(field):
                    self.add_error(field, "Required to enable or test email alerts.")
        saved_webhook = self.config and self.config.webhook_channel and self.config.webhook_channel.webhook_url_encrypted
        if (data.get("webhook_enabled") or self.test_method == "webhook") and not (data.get("webhook_url") or saved_webhook):
            self.add_error("webhook_url", "Enter the webhook URL.")
        headers = data.get("webhook_headers")
        if headers is not None and (not isinstance(headers, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) or "\n" in k + v or "\r" in k + v
            for k, v in headers.items()
        )):
            self.add_error("webhook_headers", "Enter a JSON object of header names and string values, without newlines.")
        if data.get("enabled") and not (data.get("email_enabled") or data.get("webhook_enabled")):
            self.add_error(None, "Enable at least one delivery method before enabling alerts.")
        return data

    @transaction.atomic
    def save(self):
        data = self.cleaned_data
        config, _ = AlertSettings.objects.get_or_create(pk=1)
        config = AlertSettings.objects.select_for_update().get(pk=config.pk)
        rule = config.rule or AlertRule(name=f"Certificate alert settings {uuid.uuid4().hex[:8]}")
        email = config.email_channel or AlertChannel(name=f"Settings email {uuid.uuid4().hex[:8]}", channel_type="email")
        webhook = config.webhook_channel or AlertChannel(name=f"Settings webhook {uuid.uuid4().hex[:8]}", channel_type="webhook")
        for field in ("enabled", "categories", "severities", "cooldown_minutes", "repeat_minutes", "notify_on_recovery"):
            setattr(rule, field, data[field])
        rule.expiration_days = None  # Deprecated; each certificate supplies its own lead time.
        rule.full_clean()
        rule.save()
        email.enabled = data["email_enabled"]
        for field in ("recipients", "smtp_host", "smtp_username", "smtp_verify_tls", "from_email", "subject_prefix"):
            setattr(email, field, data[field])
        email.smtp_port = data.get("smtp_port") or 587
        email.smtp_use_tls = data["smtp_security"] == "starttls"
        email.smtp_use_ssl = data["smtp_security"] == "ssl"
        if data["clear_smtp_password"]:
            email.smtp_password_encrypted = ""
        elif data["smtp_password"]:
            email.smtp_password_encrypted = encrypt_text(data["smtp_password"])
        if email.enabled:
            email.full_clean()
        email.save()
        webhook.enabled = data["webhook_enabled"]
        webhook.webhook_verify_tls = data["webhook_verify_tls"]
        if data["webhook_url"]:
            webhook.webhook_url_encrypted = encrypt_text(data["webhook_url"])
        if data["webhook_headers"] is not None:
            webhook.webhook_headers_encrypted = encrypt_json(data["webhook_headers"])
        webhook.full_clean()
        webhook.save()
        rule.channels.set([email, webhook])
        config.rule, config.email_channel, config.webhook_channel = rule, email, webhook
        config.save()
        return config


class AlertSettingsView(LoginRequiredMixin, View):
    template_name = "netbox_certificates/alert_settings.html"

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and not request.user.is_superuser:
            raise PermissionDenied("Global alert settings require a NetBox superuser.")
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        config = AlertSettings.objects.select_related("rule", "email_channel", "webhook_channel").first()
        return self.page(request, AlertSettingsForm(config=config))

    def page(self, request, form):
        sections = [
            ("When and what to send", ("enabled", "categories", "severities", "cooldown_minutes", "repeat_minutes", "notify_on_recovery")),
            ("Email alerts", ("email_enabled", "recipients", "smtp_host", "smtp_port", "smtp_username", "smtp_password", "clear_smtp_password", "smtp_security", "smtp_verify_tls", "from_email", "subject_prefix")),
            ("Webhook alerts", ("webhook_enabled", "webhook_url", "webhook_headers", "webhook_verify_tls")),
        ]
        return render(request, self.template_name, {
            "form": form,
            "sections": [(label, [form[name] for name in names]) for label, names in sections],
            "recent_events": AlertEvent.objects.select_related("channel", "finding").order_by("-created")[:20],
            "other_rule_count": AlertRule.objects.filter(enabled=True).exclude(pk=getattr(getattr(form.config, "rule", None), "pk", None)).count(),
        })

    def post(self, request):
        config = AlertSettings.objects.select_related("rule", "email_channel", "webhook_channel").first()
        action = request.POST.get("_action", "save")
        test_method = {"test_email": "email", "test_webhook": "webhook"}.get(action)
        form = AlertSettingsForm(request.POST, config=config, test_method=test_method)
        if form.is_valid():
            try:
                config = form.save()
            except SecretConfigurationError as exc:
                form.add_error(None, str(exc))
            except ValidationError as exc:
                form.add_error(None, exc.messages)
            else:
                messages.success(request, "Alert settings saved.")
                if test_method:
                    from .services.alerts_v1 import send_test_channel
                    channel = config.email_channel if test_method == "email" else config.webhook_channel
                    try:
                        send_test_channel(channel)
                    except Exception as exc:
                        messages.error(request, f"Test {test_method} failed ({type(exc).__name__}). Check the destination, credentials, and TLS settings.")
                    else:
                        messages.success(request, f"Test {test_method} sent successfully.")
                return redirect("plugins:netbox_certificates:alert_settings")
        return self.page(request, form)
