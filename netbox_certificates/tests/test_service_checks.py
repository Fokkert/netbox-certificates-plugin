import json
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.urls import reverse

from netbox_certificates.export_v1 import serialize_object
from netbox_certificates.models import Certificate
from netbox_certificates.models_v1 import AlertSettings, HealthFinding, Service
from netbox_certificates.services.health_v1 import _live_service_findings
from netbox_certificates.services.metadata_import import import_metadata
from netbox_certificates.services.backup import BackupError


class ServiceCheckTests(TestCase):
    def setUp(self):
        self.user = get_user_model().objects.create_superuser(username="checks-admin", password="test-only")
        self.service = Service.objects.create(name="Endpoint", hostname="example.com", certificate_check_enabled=True)
        Certificate.objects.bulk_create([Certificate(name="Expected", fingerprint_sha256="a" * 64)])
        self.service.certificates.add(Certificate.objects.get())
        self.settings = AlertSettings(service_checks_enabled=True)

    @patch("netbox_certificates.services.endpoint_check.certificate_fingerprint")
    def test_each_switch_prevents_network_calls(self, fetch):
        self.settings.service_checks_enabled = False
        _live_service_findings(self.service, self.settings)
        self.settings.service_checks_enabled = True
        self.service.certificate_check_enabled = False
        _live_service_findings(self.service, self.settings)
        self.service.certificate_check_enabled = True
        self.service.enabled = False
        _live_service_findings(self.service, self.settings)
        fetch.assert_not_called()

    @patch("netbox_certificates.services.endpoint_check.certificate_fingerprint")
    def test_matching_mismatching_and_failed_checks(self, fetch):
        fetch.return_value = "a" * 64
        _live_service_findings(self.service, self.settings)
        self.assertFalse(HealthFinding.objects.exists())
        fetch.return_value = "b" * 64
        _live_service_findings(self.service, self.settings)
        finding = HealthFinding.objects.get()
        self.assertEqual(finding.code, "SERVICE_CERTIFICATE_MISMATCH")
        self.assertEqual(finding.evidence["observed_sha256"], "b" * 64)
        fetch.side_effect = TimeoutError("Timed out")
        _live_service_findings(self.service, self.settings)
        self.assertTrue(HealthFinding.objects.filter(code="SERVICE_CERTIFICATE_CHECK_FAILED").exists())

    def test_scoped_restore_and_permissions(self):
        self.client.force_login(self.user)
        route = reverse("plugins:netbox_certificates:service_restore")
        self.assertContains(self.client.get(route), "Restore Services")
        data = json.dumps([serialize_object(self.service)], default=str).encode()
        with self.assertRaises(BackupError):
            import_metadata(data, self.user, kind="artifactgroup")
        response = self.client.post(route, {"upload": SimpleUploadedFile("services.json", data)})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(Service.objects.count(), 1)
        reader = get_user_model().objects.create_user(username="reader")
        self.client.force_login(reader)
        self.assertEqual(self.client.get(route).status_code, 403)

    def test_service_edit_exposes_switch(self):
        self.client.force_login(self.user)
        response = self.client.get(reverse("plugins:netbox_certificates:service_edit", args=[self.service.pk]))
        self.assertContains(response, 'name="certificate_check_enabled"')
