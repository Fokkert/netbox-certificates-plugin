from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import transaction
from django.http import HttpResponse
from django.test import RequestFactory, TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from netbox_certificates.activity import PrivateKeyAccessRecord, ServiceCheckRecord
from netbox_certificates.api.activity import ActivityAPIView
from netbox_certificates.dashboard_activity import activity_summary
from netbox_certificates.middleware import KeyAccessAuditMiddleware
from netbox_certificates.models import Certificate, PrivateKey, Service
from netbox_certificates.models_v1 import AlertSettings
from netbox_certificates.services.activity import capture_checks, record_check
from netbox_certificates.services.encryption import decrypt_private_key, encrypt_private_key, PrivateKeyEncryptionError
from netbox_certificates.services.health_v1 import _live_service_findings


class ActivityTests(TestCase):
    def setUp(self):
        self.admin = get_user_model().objects.create_superuser(username="activity-admin", password="test-only")
        self.reader = get_user_model().objects.create_user(username="activity-reader")
        self.service = Service.objects.create(name="Private endpoint", hostname="example.test", certificate_check_enabled=True)
        Certificate.objects.bulk_create([Certificate(name="Expected", fingerprint_sha256="a" * 64)])
        self.service.certificates.add(Certificate.objects.get())

    @patch("netbox_certificates.services.endpoint_check.certificate_fingerprint")
    def test_attempt_counts_and_disabled_switch(self, fetch):
        settings = AlertSettings(service_checks_enabled=False)
        _live_service_findings(self.service, settings)
        fetch.assert_not_called()
        self.assertFalse(ServiceCheckRecord.objects.exists())
        settings.service_checks_enabled = True
        fetch.side_effect = ["a" * 64, "b" * 64, TimeoutError("timeout")]
        for _ in range(3):
            _live_service_findings(self.service, settings)
        summary = activity_summary(self.admin)
        self.assertEqual(summary["check_totals"], {"match": 1, "mismatch": 1, "failed": 1})
        self.assertEqual(len(summary["check_days"]), 14)
        self.assertEqual(sum(day["total"] for day in summary["check_days"]), 3)

    def test_scope_and_read_only_api(self):
        ServiceCheckRecord.objects.create(service_id=self.service.pk, service_name=self.service.name, result="match")
        PrivateKeyAccessRecord.objects.create(key_id=1, key_name="Secret key", actor="admin", operation="material_export", result="success")
        for user, expected in ((self.admin, 1), (self.reader, 0)):
            request = APIRequestFactory().get("/activity/")
            force_authenticate(request, user=user)
            response = ActivityAPIView.as_view()(request)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.data["check_total"], expected)
            if user == self.reader:
                self.assertIsNone(response.data["key_access"])
                self.assertEqual(response.data["recent_checks"], [])
        request = APIRequestFactory().post("/activity/", {})
        force_authenticate(request, user=self.admin)
        self.assertEqual(ActivityAPIView.as_view()(request).status_code, 405)

    def test_attempt_history_survives_scan_rollback_and_expires(self):
        ServiceCheckRecord.objects.create(service_id=self.service.pk, service_name="Old", result="match", created=timezone.now()-timedelta(days=91))
        @capture_checks
        @transaction.atomic
        def scan():
            record_check(service_id=self.service.pk, service_name=self.service.name, result="failed")
            raise ValueError("Later scan failure")
        with self.assertRaises(ValueError):
            scan()
        self.assertEqual(list(ServiceCheckRecord.objects.values_list("result", flat=True)), ["failed"])

    def test_key_audit_deduplicates_and_records_failed_decryption(self):
        key = SimpleNamespace(pk=7, name="Example private key")
        token = encrypt_private_key(b"test secret material")
        def export(request):
            self.assertEqual(decrypt_private_key(token, private_key=key), b"test secret material")
            decrypt_private_key(token, private_key=key)
            return HttpResponse(status=200)
        request = RequestFactory().post("/plugins/ssl-certificates/export-inventory/")
        request.user = self.admin
        KeyAccessAuditMiddleware(export)(request)
        record = PrivateKeyAccessRecord.objects.get()
        self.assertEqual((record.actor, record.operation, record.result, record.response_status), (self.admin.username, "material_export", "success", 200))
        self.assertNotIn("test secret material", str(record.__dict__))
        def broken(request):
            with transaction.atomic():
                decrypt_private_key(b"invalid", private_key=key)
        with self.assertRaises(PrivateKeyEncryptionError):
            KeyAccessAuditMiddleware(broken)(request)
        self.assertTrue(PrivateKeyAccessRecord.objects.filter(result="failed", response_status=500).exists())

    def test_audit_persistence_failure_blocks_material_response(self):
        key = SimpleNamespace(pk=7, name="Example private key")
        token = encrypt_private_key(b"test material")
        def export(request):
            return HttpResponse(decrypt_private_key(token, private_key=key))
        request = RequestFactory().get("/download/privatekey/7/")
        request.user = self.admin
        with patch.object(PrivateKeyAccessRecord.objects, "bulk_create", side_effect=RuntimeError("Audit unavailable")):
            with self.assertRaises(RuntimeError):
                KeyAccessAuditMiddleware(export)(request)

    def test_dashboard_is_scoped_and_does_not_probe_services(self):
        self.client.force_login(self.admin)
        with patch("netbox_certificates.services.endpoint_check.certificate_fingerprint") as fetch:
            response = self.client.get("/plugins/ssl-certificates/dashboard/")
        self.assertContains(response, "Live certificate checks")
        self.assertContains(response, "Recent private-key access")
        fetch.assert_not_called()
        self.client.force_login(self.reader)
        self.assertNotContains(self.client.get("/plugins/ssl-certificates/dashboard/"), "Recent private-key access")

    def test_real_download_uses_audit_middleware(self):
        PrivateKey.objects.bulk_create([PrivateKey(
            name="Download key", encrypted_material=encrypt_private_key(b"test key material"),
            public_key_fingerprint="b" * 64, material_sha256="c" * 64,
        )])
        key = PrivateKey.objects.get()
        url = f"/plugins/ssl-certificates/download/privatekey/{key.pk}/"
        self.client.force_login(self.admin)
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        record = PrivateKeyAccessRecord.objects.get()
        self.assertEqual((record.key_id, record.actor, record.response_status), (key.pk, self.admin.username, 200))
        self.client.force_login(self.reader)
        self.assertEqual(self.client.get(url).status_code, 403)
        self.assertEqual(PrivateKeyAccessRecord.objects.count(), 1)
