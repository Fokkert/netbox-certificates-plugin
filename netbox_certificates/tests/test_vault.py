from types import SimpleNamespace
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from netbox_certificates.api.preferences import PreferencesAPIView
from netbox_certificates.models import Certificate
from netbox_certificates.models_v1 import AlertSettings, HealthFinding, Service


class VaultTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_superuser(username="vault-admin", password="test-only")
        cls.service = Service.objects.create(name="Visible endpoint")
        ct = ContentType.objects.get_for_model(Service)
        HealthFinding.objects.bulk_create([
            HealthFinding(code=f"TEST_{n}", category="service", severity="warning", summary=f"Vault finding {n}",
                          object_type=ct, object_id=cls.service.pk, fingerprint=f"{n:064x}", evidence={"example": "Evidence value"})
            for n in range(26)
        ])

    def setUp(self):
        self.client.force_login(self.user)
        self.url = reverse("plugins:netbox_certificates:dashboard")

    def test_combined_dashboard_and_legacy_filters(self):
        response = self.client.get(self.url)
        for text in ("Dashboard", "Inventory", "Certificate expiration", "Health findings", "Visible endpoint"):
            self.assertContains(response, text)
        for name in ("health", "healthfinding_list", "expiration_dashboard"):
            self.assertRedirects(self.client.get(reverse(f"plugins:netbox_certificates:{name}") + "?severity=warning"), self.url + "?severity=warning")
        response = self.client.get(self.url + "?severity=&status=&q=")
        self.assertFalse(response.context["filter_errors"])
        self.assertEqual(response.context["findings"].paginator.count, 26)

    def test_preferences_control_sections_and_pagination(self):
        AlertSettings.objects.update_or_create(pk=1, defaults={"vault_findings_per_page": 25,
            "vault_show_expiration": False, "vault_show_assignments": False, "vault_show_evidence": False})
        response = self.client.get(self.url)
        self.assertEqual(len(response.context["findings"]), 25)
        self.assertNotContains(response, "<h2>Certificate expiration</h2>")
        self.assertNotContains(response, "Without a direct service assignment")
        self.assertNotContains(response, "<th>Evidence</th>")
        self.assertNotContains(response, "Evidence value")
        response = self.client.get(self.url + "?page=2")
        self.assertEqual(len(response.context["findings"]), 1)

    def test_preference_api_validation_and_partial_updates(self):
        def patch(data):
            request = APIRequestFactory().patch("/preferences/", data, format="json")
            force_authenticate(request, user=self.user, token=SimpleNamespace(write_enabled=True))
            return PreferencesAPIView.as_view()(request)
        self.assertEqual(patch({"vault_findings_per_page": 0}).status_code, 400)
        self.assertEqual(patch({"vault_expiration_limit": 1000}).status_code, 400)
        response = patch({"vault_expiration_limit": 10, "vault_show_evidence": False})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data["vault_expiration_limit"], 10)
        self.assertFalse(response.data["vault_show_evidence"])
        self.assertTrue(response.data["vault_show_expiration"])

    def test_expiration_limit_and_warning_window(self):
        Certificate.objects.bulk_create([
            Certificate(name=f"Certificate {n}", fingerprint_sha256=f"{n:064x}",
                        valid_to=timezone.now() + timedelta(days=40 + n)) for n in range(12)
        ])
        AlertSettings.objects.update_or_create(pk=1, defaults={"vault_expiration_limit": 10, "expiration_warning_days": 90})
        response = self.client.get(self.url)
        self.assertEqual(len(response.context["upcoming"]), 10)
        self.assertEqual(response.context["counts"]["warning"], 12)
        self.assertContains(response, "Showing up to 10 certificates")

    def test_dashboard_does_not_disclose_unpermitted_objects(self):
        user = get_user_model().objects.create_user(username="vault-unprivileged")
        self.client.force_login(user)
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "Visible endpoint")
        self.assertNotContains(response, "Vault finding 0")
        self.assertEqual(response.context["findings"].paginator.count, 0)
