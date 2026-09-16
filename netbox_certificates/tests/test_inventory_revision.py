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
