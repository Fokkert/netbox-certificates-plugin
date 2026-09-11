"""Run with NetBox's manage.py test netbox_certificates.tests on a test database."""
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.urls import reverse

from netbox_certificates.models import ArtifactGroup
from netbox_certificates.models_v1 import HealthFinding, Service


class RevisionUIIntegrationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_superuser(username="revision-test-admin", password="example-test-only")
        cls.parent = ArtifactGroup.objects.create(name="Root")
        cls.child = ArtifactGroup.objects.create(name="Child", parent=cls.parent)
        cls.finding = HealthFinding.objects.create(
            code="TEST_FINDING", category="validity", severity="critical", summary="Test health finding",
            object_type=ContentType.objects.get_for_model(ArtifactGroup), object_id=cls.parent.pk,
            fingerprint="a" * 64,
            related_type=ContentType.objects.get_for_model(ArtifactGroup), related_object_id=cls.child.pk,
            evidence={"days_remaining": 5},
        )

    def setUp(self):
        self.client.force_login(self.user)

    def url(self, name, **kwargs):
        return reverse(f"plugins:netbox_certificates:{name}", kwargs=kwargs)

    def test_health_list_and_detail_render_for_superuser(self):
        response = self.client.get(self.url("health"))
        self.assertContains(response, "Test health finding")
        self.assertContains(response, "Certificate expiration")
        for response in (response, self.client.get(self.url("healthfinding", pk=self.finding.pk))):
            self.assertContains(response, f'href="{self.parent.get_absolute_url()}"')
            self.assertContains(response, f'href="{self.child.get_absolute_url()}"')
            self.assertContains(response, "Days remaining")
        self.assertEqual(self.client.get(self.url("healthfinding_edit", pk=self.finding.pk)).status_code, 200)
        self.assertRedirects(self.client.get(self.url("expiration_dashboard")), self.url("health"))

    def test_folders_and_services_render(self):
        response = self.client.get(self.url("artifactgroup_list"))
        self.assertContains(response, "Root")
        self.assertContains(response, "Child")
        self.assertNotContains(response, 'id="filters-form"')
        self.assertEqual(self.client.get(self.url("service_list")).status_code, 200)
        self.assertEqual(self.client.get(self.url("service_add")).status_code, 200)

    def test_simple_service_form_derives_endpoint(self):
        response = self.client.post(self.url("service_add"), {
            "name": "Test HTTPS service", "status": "active", "service_type": "website",
            "environment": "lab", "deployment": "Nginx", "protocol": "https",
            "primary_url": "https://service.example.test:8443/", "criticality": "medium", "enabled": "on",
        })
        self.assertEqual(response.status_code, 302, getattr(response, "context", None))
        service = Service.objects.get(name="Test HTTPS service")
        self.assertEqual((service.hostname, service.sni_name, service.port),
                         ("service.example.test", "service.example.test", 8443))

    def test_group_add_edit_and_service_membership(self):
        service = Service.objects.create(name="Group service")
        for name, kwargs in (("artifactgroup_add", {}), ("artifactgroup_edit", {"pk": self.child.pk})):
            response = self.client.get(self.url(name, **kwargs))
            self.assertContains(response, "Group service")
        response = self.client.post(self.url("artifactgroup_add"), {
            "name": "New group", "parent": self.parent.pk, "members": [f"service:{service.pk}"],
        })
        self.assertEqual(response.status_code, 302)
        group = ArtifactGroup.objects.get(name="New group")
        self.assertEqual(group.parent, self.parent)
        self.assertTrue(group.services.filter(pk=service.pk).exists())
        response = self.client.post(self.url("artifactgroup_edit", pk=group.pk), {
            "name": "Renamed group", "parent": self.parent.pk, "members": [f"service:{service.pk}"],
        })
        self.assertEqual(response.status_code, 302)
        group.refresh_from_db()
        self.assertEqual(group.name, "Renamed group")
        self.assertTrue(group.services.filter(pk=service.pk).exists())

    def test_alert_settings_and_history_render(self):
        response = self.client.get(self.url("alert_settings"))
        self.assertContains(response, "Verify SMTP TLS certificate")
        self.assertContains(response, "Verify webhook TLS certificate")
        self.assertEqual(self.client.get(self.url("alertevent_list")).status_code, 200)

    def test_unprivileged_user_cannot_write_alert_settings(self):
        user = get_user_model().objects.create_user(username="revision-no-permissions", password="example-test-only")
        self.client.force_login(user)
        self.assertEqual(self.client.get(self.url("alert_settings")).status_code, 403)
        self.assertEqual(self.client.post(self.url("alert_settings"), {"enabled": "on"}).status_code, 403)
