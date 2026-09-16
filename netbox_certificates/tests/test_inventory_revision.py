"""Optional integration coverage: run using a disposable NetBox test database."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.apps import apps

from netbox_certificates.models import Bundle, Certificate, CSR, PrivateKey
from netbox_certificates.services.unified_import import UnifiedImportError, UploadItem, import_objects


class InventoryRevisionTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_superuser(username="inventory-test-admin", password="test-only")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.test")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(1).not_valid_before(now).not_valid_after(now + timedelta(days=30))
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(key, hashes.SHA256()))
        csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
        cls.material = (cert.public_bytes(serialization.Encoding.PEM)
                        + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
                        + csr.public_bytes(serialization.Encoding.PEM))

    def setUp(self):
        self.client.force_login(self.user)
        encryption = patch("netbox_certificates.services.encryption._fernet", return_value=Fernet(Fernet.generate_key()))
        encryption.start()
        self.addCleanup(encryption.stop)

    def import_batch(self, **kwargs):
        return import_objects(uploads=[UploadItem("mixed.pem", self.material)],
                              allowed_kinds={"certificate", "private_key", "csr"}, user=self.user, **kwargs)

    def test_mixed_import_reuses_objects_and_preserves_relationships(self):
        result = self.import_batch()
        self.assertEqual(len(result["created"]), 3)
        from netbox_certificates.models_v1 import ObjectLink
        self.assertTrue(ObjectLink.objects.filter(automatic=True, relationship="key_match").exists())
        self.assertFalse(ObjectLink.objects.filter(automatic=False).exists())
        bundle = Bundle.objects.get()
        self.assertEqual(bundle.certificate_id, Certificate.objects.get().pk)
        self.assertEqual(bundle.private_key_id, PrivateKey.objects.get().pk)
        self.assertEqual(bundle.csr_id, CSR.objects.get().pk)
        repeated = self.import_batch()
        self.assertEqual(len(repeated["created"]), 0)
        self.assertEqual(len(repeated["reused"]), 3)
        self.assertEqual(Bundle.objects.count(), 1)

    def test_database_validation_failure_rolls_back_batch(self):
        with self.assertRaises(UnifiedImportError):
            self.import_batch(description="x" * 201)
        for model in (Certificate, PrivateKey, CSR, Bundle):
            self.assertEqual(model.objects.count(), 0)

    def test_existing_key_csr_generation_does_not_create_another_key(self):
        self.import_batch()
        key = PrivateKey.objects.get()
        response = self.client.post(reverse("plugins:netbox_certificates:csr_generate"), {
            "common_name": "renewed.example.test", "existing_private_key": key.pk,
            "key_algorithm": "rsa", "rsa_bits": "2048", "ec_curve": "secp256r1",
            "signature_hash": "sha256", "rsa_signature": "pkcs1v15", "sans": "DNS:renewed.example.test",
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(PrivateKey.objects.count(), 1)
        csr = CSR.objects.get(name="renewed.example.test")
        self.assertEqual(csr.public_key_fingerprint, key.public_key_fingerprint)
        self.assertTrue(x509.load_pem_x509_csr(csr.material.encode("ascii")).is_signature_valid)

    def test_empty_export_and_retired_policy_bookmark(self):
        response = self.client.get(reverse("plugins:netbox_certificates:certificateauthority_material_export"))
        self.assertContains(response, "There are no objects available to export")
        self.assertNotIn("Content-Disposition", response)
        self.assertRedirects(self.client.get(reverse("plugins:netbox_certificates:certificatepolicy_list")),
                             reverse("plugins:netbox_certificates:alert_settings"))

    def test_all_public_serializers_support_netbox_lookup(self):
        from utilities.api import get_serializer_for_model
        from netbox.models.features import model_is_public
        for model in apps.get_app_config("netbox_certificates").get_models():
            if model_is_public(model):
                with self.subTest(model=model.__name__):
                    self.assertIs(get_serializer_for_model(model).Meta.model, model)

    def test_delete_event_serialization_accepts_no_request(self):
        from extras.events import serialize_for_event
        from netbox_certificates.models_v1 import ObjectLink
        self.import_batch()
        for obj in list(ObjectLink.objects.all()) + [Certificate.objects.get(), PrivateKey.objects.get(), CSR.objects.get(), Bundle.objects.get()]:
            with self.subTest(model=type(obj).__name__):
                self.assertEqual(serialize_for_event(obj)["id"], obj.pk)

    def test_single_and_bulk_deletion_with_generated_links(self):
        from netbox_certificates.models_v1 import ObjectLink
        self.import_batch()
        certificate = Certificate.objects.get()
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("plugins:netbox_certificates:certificate_delete", args=[certificate.pk]),
                                        {"confirm": True})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Certificate.objects.exists())
        # Reimport, then exercise bulk confirmation through the actual NetBox view.
        self.import_batch()
        with self.captureOnCommitCallbacks(execute=True):
            response = self.client.post(reverse("plugins:netbox_certificates:certificate_bulk_delete"),
                                        {"pk": list(Certificate.objects.values_list("pk", flat=True)), "_confirm": True})
        self.assertEqual(response.status_code, 302)
        self.assertFalse(Certificate.objects.exists())
        self.assertFalse(ObjectLink.objects.filter(source_type__model="certificate").exists())
        self.assertFalse(ObjectLink.objects.filter(target_type__model="certificate").exists())

    def test_supersedes_and_subject_are_not_writable(self):
        from netbox_certificates.api.serializers import CertificateSerializer
        from netbox_certificates.forms import CertificateForm
        self.import_batch()
        certificate = Certificate.objects.get()
        for field in ("supersedes", "parent_certificate", "subject", "is_ca"):
            serializer = CertificateSerializer(certificate, data={field: 1}, partial=True)
            self.assertFalse(serializer.is_valid())
            self.assertIn(field, serializer.errors)
        form = CertificateForm(instance=certificate, user=self.user)
        self.assertNotIn("supersedes", form.fields)
        self.assertTrue(form.fields["material"].disabled)

    def test_preferences_validate_and_restrict_access(self):
        url = reverse("plugins:netbox_certificates:preferences")
        self.assertContains(self.client.get(url), "Health scan frequency")
        response = self.client.post(url, {"health_scan_enabled": True, "health_scan_interval_minutes": 30,
            "alert_interval_minutes": 15, "expiration_warning_days": 90, "csr_rsa_bits": 3072,
            "import_chain_default": True, "preserve_archive_default": True})
        self.assertEqual(response.status_code, 302)
        user = get_user_model().objects.create_user(username="preferences-no-permission")
        self.client.force_login(user)
        self.assertEqual(self.client.get(url).status_code, 403)

    def test_ca_bookmark_uses_filtered_certificates(self):
        self.assertRedirects(self.client.get(reverse("plugins:netbox_certificates:certificateauthority_list")),
                             reverse("plugins:netbox_certificates:certificate_list") + "?is_ca=true")
