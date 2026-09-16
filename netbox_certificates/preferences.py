"""Global operational preferences; notification transports remain in Alerts."""
from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.shortcuts import redirect, render
from django.views import View

from .models_v1 import AlertSettings


PREFERENCE_FIELDS = (
    "health_scan_enabled", "health_scan_interval_minutes", "alert_interval_minutes",
    "expiration_warning_days", "import_chain_default", "preserve_archive_default", "csr_rsa_bits",
)
INTERVALS = [(n, f"Every {n} minutes") for n in (5, 15, 30, 60, 180, 360, 720, 1440)]


def get_preferences():
    return AlertSettings.objects.filter(pk=1).first() or AlertSettings()


class PreferencesForm(forms.ModelForm):
    health_scan_enabled = forms.BooleanField(required=False, label="Enable scheduled health scans",
        help_text="Manual scans remain available. Alerts use the latest stored findings when scheduled scans are disabled.")
    health_scan_interval_minutes = forms.TypedChoiceField(choices=INTERVALS, coerce=int, label="Health scan frequency")
    alert_interval_minutes = forms.TypedChoiceField(choices=INTERVALS, coerce=int, label="Alert evaluation frequency",
        help_text="Controls when delivery rules are evaluated; per-certificate expiration timing is unchanged.")
    expiration_warning_days = forms.IntegerField(min_value=30, max_value=3650, label="Upcoming-expiration findings (days)",
        help_text="The overview warning window. A certificate's own alert trigger can still create an earlier finding.")
    import_chain_default = forms.BooleanField(required=False, label="Include certificate chains by default")
    preserve_archive_default = forms.BooleanField(required=False, label="Preserve single-bundle source archives by default")
    csr_rsa_bits = forms.TypedChoiceField(choices=[(n, str(n)) for n in (2048, 3072, 4096, 8192)], coerce=int,
        label="Default RSA size for new CSR keys")

    class Meta:
        model = AlertSettings
        fields = PREFERENCE_FIELDS

    @transaction.atomic
    def save(self, commit=True):
        # Save only preferences, preserving concurrent alert settings and job timestamps.
        config, _ = AlertSettings.objects.get_or_create(pk=1)
        config = AlertSettings.objects.select_for_update().get(pk=config.pk)
        for name in PREFERENCE_FIELDS:
            setattr(config, name, self.cleaned_data[name])
        config.full_clean()
        if commit:
            config.save(update_fields=PREFERENCE_FIELDS)
        return config


class PreferencesView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and not request.user.is_superuser:
            raise PermissionDenied("Plugin preferences require a NetBox superuser.")
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        return self.page(request, PreferencesForm(instance=get_preferences()))

    def post(self, request):
        form = PreferencesForm(request.POST, instance=get_preferences())
        if form.is_valid():
            form.save()
            messages.success(request, "Plugin preferences saved.")
            return redirect("plugins:netbox_certificates:preferences")
        return self.page(request, form)

    @staticmethod
    def page(request, form):
        groups = (
            ("Background processing", ("health_scan_enabled", "health_scan_interval_minutes", "alert_interval_minutes")),
            ("Health overview", ("expiration_warning_days",)),
            ("Import defaults", ("import_chain_default", "preserve_archive_default")),
            ("CSR defaults", ("csr_rsa_bits",)),
        )
        return render(request, "netbox_certificates/preferences.html", {
            "form": form, "sections": [(title, [form[name] for name in names]) for title, names in groups],
            "preferences": get_preferences(),
        })
