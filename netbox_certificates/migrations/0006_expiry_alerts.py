import django.db.models.deletion
import netbox.models.deletion
import taggit.managers
import utilities.json
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0005_certificate_supersedes_and_permissions")]
    operations = [
        migrations.AddField(model_name="certificate", name="alert_trigger", field=models.CharField(blank=True, choices=[("year", "Year"), ("month", "Month"), ("week", "Week"), ("day", "Day"), ("hour", "Hour"), ("minute", "Minute"), ("second", "Second")], max_length=16, verbose_name="ALERT TRIGGER")),
        migrations.AddField(model_name="certificate", name="trigger_value", field=models.PositiveIntegerField(blank=True, null=True, verbose_name="TRIGGER VALUE")),
        migrations.CreateModel(
            name="ExpiryAlertConfiguration",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ("check_interval_minutes", models.PositiveIntegerField(default=60)),
                ("email_enabled", models.BooleanField(default=False)),
                ("smtp_host", models.CharField(blank=True, max_length=255)),
                ("smtp_port", models.PositiveIntegerField(default=587)),
                ("smtp_username", models.CharField(blank=True, max_length=255)),
                ("smtp_password_encrypted", models.BinaryField(blank=True, editable=False, null=True)),
                ("smtp_use_tls", models.BooleanField(default=True)),
                ("smtp_use_ssl", models.BooleanField(default=False)),
                ("email_from_address", models.EmailField(blank=True, max_length=254)),
                ("email_recipients", models.TextField(blank=True)),
                ("include_superusers", models.BooleanField(default=True)),
                ("webhook_enabled", models.BooleanField(default=False)),
                ("webhook_url_encrypted", models.BinaryField(blank=True, editable=False, null=True)),
                ("webhook_bearer_token_encrypted", models.BinaryField(blank=True, editable=False, null=True)),
                ("webhook_allow_http", models.BooleanField(default=False)),
                ("last_check_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("last_check_success", models.BooleanField(blank=True, editable=False, null=True)),
                ("last_check_message", models.CharField(blank=True, editable=False, max_length=500)),
                ("email_last_test_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("email_last_test_success", models.BooleanField(blank=True, editable=False, null=True)),
                ("email_last_test_message", models.CharField(blank=True, editable=False, max_length=500)),
                ("webhook_last_test_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("webhook_last_test_success", models.BooleanField(blank=True, editable=False, null=True)),
                ("webhook_last_test_message", models.CharField(blank=True, editable=False, max_length=500)),
                ("tags", taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag")),
            ],
            options={"verbose_name": "expiry alert configuration", "verbose_name_plural": "expiry alert configuration", "default_permissions": ("add", "change", "view"), "permissions": (("test_expiryalertconfiguration", "Can test expiry alert configuration"),)},
            bases=(netbox.models.deletion.DeleteMixin, models.Model),
        ),
        migrations.CreateModel(
            name="ExpiryAlertEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False)),
                ("created", models.DateTimeField(auto_now_add=True, null=True)),
                ("last_updated", models.DateTimeField(auto_now=True, null=True)),
                ("custom_field_data", models.JSONField(blank=True, default=dict, encoder=utilities.json.CustomFieldJSONEncoder)),
                ("method", models.CharField(choices=[("email", "Email"), ("webhook", "Webhook")], max_length=16)),
                ("certificate_valid_to", models.DateTimeField()),
                ("trigger_unit", models.CharField(choices=[("year", "Year"), ("month", "Month"), ("week", "Week"), ("day", "Day"), ("hour", "Hour"), ("minute", "Minute"), ("second", "Second")], max_length=16)),
                ("trigger_value", models.PositiveIntegerField()),
                ("trigger_at", models.DateTimeField()),
                ("last_attempt_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("delivered_at", models.DateTimeField(blank=True, editable=False, null=True)),
                ("success", models.BooleanField(default=False, editable=False)),
                ("attempt_count", models.PositiveIntegerField(default=0, editable=False)),
                ("status_code", models.PositiveIntegerField(blank=True, editable=False, null=True)),
                ("message", models.CharField(blank=True, editable=False, max_length=500)),
                ("certificate", models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="expiry_alert_events", to="netbox_certificates.certificate")),
                ("tags", taggit.managers.TaggableManager(through="extras.TaggedItem", to="extras.Tag")),
            ],
            options={"verbose_name": "expiry alert event", "verbose_name_plural": "expiry alert events", "ordering": ("-last_attempt_at", "-created"), "default_permissions": ("view", "delete"), "constraints": [models.UniqueConstraint(fields=("certificate", "method", "certificate_valid_to", "trigger_unit", "trigger_value"), name="netbox_certificates_unique_expiry_alert_event")]},
            bases=(netbox.models.deletion.DeleteMixin, models.Model),
        ),
    ]
