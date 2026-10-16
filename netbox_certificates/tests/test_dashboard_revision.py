import importlib
from types import SimpleNamespace

from django.apps import apps
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIRequestFactory, force_authenticate

from netbox_certificates.api.alert_settings import AlertSettingsAPIView
from netbox_certificates.api.preferences import PreferencesAPIView
from netbox_certificates.models_v1 import AlertSettings, AlertRule


class DashboardRevisionTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(username="dashboard-admin", password="test-only")
        self.client.force_login(self.user)

    def patch(self, view, data):
        request = APIRequestFactory().patch("/settings/", data, format="json")
        force_authenticate(request, user=self.user, token=SimpleNamespace(write_enabled=True))
        return view.as_view()(request)

    def test_switch_moved_without_resetting_value(self):
        AlertSettings.objects.update_or_create(pk=1, defaults={"service_checks_enabled": True})
        self.assertNotContains(self.client.get(reverse("plugins:netbox_certificates:preferences")), 'name="service_checks_enabled"')
        response = self.client.get(reverse("plugins:netbox_certificates:alert_settings"))
        self.assertContains(response, 'type="checkbox" name="service_checks_enabled"', count=1)
        self.assertNotContains(response, "Weak or reused keys")
        self.assertEqual(self.patch(PreferencesAPIView, {"vault_show_evidence": False}).status_code, 200)
        self.assertTrue(AlertSettings.objects.get().service_checks_enabled)
        self.assertEqual(self.patch(PreferencesAPIView, {"service_checks_enabled": False}).status_code, 400)
        response = self.patch(AlertSettingsAPIView, {"service_checks_enabled": False})
        self.assertEqual(response.status_code, 200, response.data)
        self.assertFalse(AlertSettings.objects.get().service_checks_enabled)

    def test_dashboard_redirect_and_removed_page(self):
        dashboard = reverse("plugins:netbox_certificates:dashboard")
        self.assertContains(self.client.get(dashboard), "Dashboard")
        for name in ("vault", "health", "expiration_dashboard"):
            self.assertRedirects(self.client.get(reverse(f"plugins:netbox_certificates:{name}") + "?severity=warning"), dashboard + "?severity=warning")
        self.assertEqual(self.client.get("/plugins/ssl-certificates/backup/").status_code, 404)

    def test_retired_category_migration_preserves_other_choices_and_live_switch(self):
        rule = AlertRule.objects.create(name="Managed", categories=["security", "service"], enabled=True)
        AlertSettings.objects.update_or_create(pk=1, defaults={"rule": rule, "service_checks_enabled": True})
        migration = importlib.import_module("netbox_certificates.migrations.0030_retire_security_alert_option")
        editor = SimpleNamespace(connection=SimpleNamespace(alias="default"))
        migration.retire_option(apps, editor)
        rule.refresh_from_db()
        self.assertEqual(rule.categories, ["service"])
        self.assertTrue(rule.enabled)
        self.assertTrue(AlertSettings.objects.get().service_checks_enabled)
        rule.categories = ["security"]
        rule.save()
        migration.retire_option(apps, editor)
        rule.refresh_from_db()
        self.assertFalse(rule.enabled)
        self.assertNotIn("security", rule.categories)
