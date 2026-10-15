"""Database-backed coverage for typed groups, naming, tables, and repeat timing."""
from datetime import timedelta
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db import transaction
from django.test import RequestFactory, TestCase
from django.urls import reverse
from django.utils import timezone

from netbox_certificates.alert_settings import AlertSettingsForm
from netbox_certificates.api.base_serializers import ArtifactGroupSerializer
from netbox_certificates.api.v1_serializers import ServiceSerializer
from netbox_certificates.models import ArtifactGroup, Bundle, Certificate, CSR, PrivateKey
from netbox_certificates.models_v1 import AlertChannel, AlertEvent, AlertRule, Service
from netbox_certificates.services.alerts_v1 import dispatch_alerts
from netbox_certificates.services.health_v1 import _finding
from netbox_certificates.services.naming import identity_name
from netbox_certificates.services.unified_import import UploadItem, import_objects
from netbox_certificates.tables import BundleTable, CertificateTable, CSRTable, PrivateKeyTable
from netbox_certificates.tables_v1 import ServiceTable


class Revision140Tests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_superuser(username="revision-140", password="test-only")
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        # An internal-PKI subject with no CN, exactly the reported class of input.
        cls.subject = x509.Name([x509.NameAttribute(x509.NameOID.EMAIL_ADDRESS, "admin@example.test"),
                                 x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "Internal PKI")])
        now = timezone.now()
        cls.cert = (x509.CertificateBuilder().subject_name(cls.subject).issuer_name(cls.subject)
                    .public_key(cls.key.public_key()).serial_number(140)
                    .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=90))
                    .add_extension(x509.SubjectAlternativeName([x509.DNSName("pmg.example.test")]), critical=False)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .sign(cls.key, hashes.SHA256()))

    def setUp(self):
        self.client.force_login(self.user)
        self.request = RequestFactory().get("/")
        self.request.user = self.user

    def import_pfx(self, groups=None):
        data = pkcs12.serialize_key_and_certificates(b"ignored-friendly-name", self.key, self.cert, None,
                                                   serialization.BestAvailableEncryption(b"test"))
        return import_objects(uploads=[UploadItem("legacy.pfx", data)],
                              allowed_kinds={"certificate", "private_key", "csr"}, user=self.user,
                              password="test", groups=groups)

    def test_pfx_names_and_typed_import_assignment(self):
        cert_group = ArtifactGroup.objects.create(name="Certificates", group_type="certificate")
        bundle_group = ArtifactGroup.objects.create(name="Bundles", group_type="bundle")
        self.import_pfx(groups=[cert_group, bundle_group])
        certificate, key, bundle = Certificate.objects.get(), PrivateKey.objects.get(), Bundle.objects.get()
        self.assertEqual(certificate.name, "pmg.example.test")
        self.assertEqual(key.name, "pmg.example.test Private key")
        self.assertEqual(list(certificate.groups.all()), [cert_group])
        self.assertEqual(list(bundle.groups.all()), [bundle_group])
        self.assertFalse(key.groups.exists())
        self.assertEqual(certificate.subject, self.subject.rfc4514_string())

    def test_standalone_key_later_matched_and_custom_name_preserved(self):
        pem = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        import_objects(uploads=[UploadItem("server.key", pem)], allowed_kinds={"private_key"}, user=self.user)
        key = PrivateKey.objects.get()
        self.assertIn("Unmatched private key", key.name)
        self.import_pfx()
        key.refresh_from_db()
        self.assertEqual(key.name, "pmg.example.test Private key")
        key.name = "Do not rename me"
        key.save()
        self.import_pfx()
        key.refresh_from_db()
        self.assertEqual(key.name, "Do not rename me")

    def test_identity_fallbacks(self):
        self.assertEqual(identity_name(self.subject, ["DNS:*.example.test"], "fallback"), "*.example.test")
        odd_cn = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "O=PKI,C=IR")])
        self.assertEqual(identity_name(odd_cn, ["IP:192.0.2.1"], "fallback"), "192.0.2.1")
        self.assertEqual(identity_name(x509.Name([]), [], "Certificate abc"), "Certificate abc")

    def test_group_constraints_in_both_directions_and_api(self):
        root = ArtifactGroup.objects.create(name="Root", group_type="group")
        group = ArtifactGroup.objects.create(name="Service group", group_type="service", parent=root)
        certificate_group = ArtifactGroup.objects.create(name="Certificate group", group_type="certificate")
        service = Service.objects.create(name="Endpoint")
        group.services.add(service)
        with self.assertRaises(ValidationError), transaction.atomic():
            service.groups.add(certificate_group)
        with self.assertRaises(ValidationError), transaction.atomic():
            certificate_group.services.add(service)
        invalid = ArtifactGroup(name="Invalid child", parent=group)
        with self.assertRaises(ValidationError):
            invalid.full_clean()
        group.group_type = "certificate"
        with self.assertRaises(ValidationError):
            group.full_clean()
        serializer = ServiceSerializer(service, data={"groups": [certificate_group.pk]}, partial=True,
                                       context={"request": self.request})
        self.assertFalse(serializer.is_valid())
        self.assertIn("groups", serializer.errors)
        serializer = ArtifactGroupSerializer(data={"name": "Wrong members", "group_type": "certificate", "services": [service.pk]},
                                              context={"request": self.request})
        self.assertFalse(serializer.is_valid())

    def test_group_ui_rejects_wrong_members_and_renders_type(self):
        service = Service.objects.create(name="Endpoint")
        url = reverse("plugins:netbox_certificates:artifactgroup_add")
        response = self.client.post(url, {"name": "Wrong type", "group_type": "certificate", "member_service": [service.pk]})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Select only members matching this group type")
        self.assertFalse(ArtifactGroup.objects.filter(name="Wrong type").exists())
        group = ArtifactGroup.objects.create(name="Endpoints", group_type="service")
        group.services.add(service)
        detail = self.client.get(group.get_absolute_url())
        self.assertContains(detail, "Endpoint")
        self.assertContains(detail, "Group type")
        self.assertNotContains(detail, '<h3 class="h6">Private Keys</h3>')

    def test_generated_csr_assigns_only_matching_group_types(self):
        csr_group = ArtifactGroup.objects.create(name="Requests", group_type="csr")
        key_group = ArtifactGroup.objects.create(name="Keys", group_type="privatekey")
        bundle_group = ArtifactGroup.objects.create(name="Generated bundles", group_type="bundle")
        response = self.client.post(reverse("plugins:netbox_certificates:csr_generate"), {
            "common_name": "generated.example.test", "key_algorithm": "rsa", "rsa_bits": 2048,
            "ec_curve": "secp256r1", "signature_hash": "sha256", "rsa_signature": "pkcs1v15",
            "sans": "DNS:generated.example.test", "groups": [csr_group.pk, key_group.pk, bundle_group.pk],
        })
        self.assertEqual(response.status_code, 302)
        self.assertEqual(list(CSR.objects.get().groups.all()), [csr_group])
        self.assertEqual(list(PrivateKey.objects.get().groups.all()), [key_group])
        self.assertEqual(list(Bundle.objects.get().groups.all()), [bundle_group])
        self.assertEqual(PrivateKey.objects.get().name, "generated.example.test Private key")

    def test_table_options_and_relationship_permissions(self):
        self.import_pfx()
        certificate, key, bundle = Certificate.objects.get(), PrivateKey.objects.get(), Bundle.objects.get()
        service = Service.objects.create(name="Endpoint")
        service.certificates.add(certificate)
        service.private_keys.add(key)
        service.bundles.add(bundle)
        expected = {ServiceTable: {"certificates", "bundles", "private_keys", "csrs", "protocol", "contact", "created", "comments"},
                    CertificateTable: {"services", "subject", "subject_alternative_names", "serial_number", "curve", "supersedes"},
                    PrivateKeyTable: {"services", "source_filename", "encrypted_on_import"},
                    CSRTable: {"services", "signature_algorithm", "subject_alternative_names"},
                    BundleTable: {"services", "source_filename", "import_report"}}
        for cls, fields in expected.items():
            self.assertTrue(fields <= set(cls.base_columns), (cls.__name__, fields - set(cls.base_columns)))
            self.assertFalse({"encrypted_material", "encrypted_archive"} & set(cls.base_columns))
        table = ServiceTable([service])
        table.request = self.request
        for field, obj in (("certificates", certificate), ("private_keys", key), ("bundles", bundle)):
            self.assertIn(obj.get_absolute_url(), str(table.rows[0].get_cell(field)))
        self.request.user = get_user_model().objects.create_user(username="no-related-access")
        self.assertNotIn(certificate.name, str(table.rows[0].get_cell("certificates")))

    def test_repeat_days_validation(self):
        values = {"categories": ["validity"], "cooldown_minutes": 60, "repeat_days": 7,
                  "smtp_security": "starttls", "subject_prefix": "Test"}
        for days, minutes in ((7, 10080), (0, 0), (2.5, 3600)):
            form = AlertSettingsForm({**values, "repeat_days": days})
            self.assertTrue(form.is_valid(), form.errors)
            self.assertEqual(form.cleaned_data["repeat_minutes"], minutes)
        form = AlertSettingsForm({**values, "repeat_days": -1})
        self.assertFalse(form.is_valid())

    def test_daily_rescans_do_not_reset_seven_day_repeat(self):
        service = Service.objects.create(name="Scanned endpoint")
        rule = AlertRule.objects.create(name="Weekly", repeat_minutes=7 * 1440, cooldown_minutes=60)
        channel = AlertChannel.objects.create(name="Test only", channel_type="email")
        rule.channels.add(channel)
        finding = _finding("TEST_REPEAT", "service", "warning", service, "Problem", evidence={"days": 20})
        with patch("netbox_certificates.services.alerts_v1._deliver") as deliver:
            self.assertEqual(dispatch_alerts([rule.pk])["delivered"], 1)
            original = finding.first_detected
            for day in range(1, 7):
                with patch("netbox_certificates.services.alerts_v1.timezone.now", return_value=original + timedelta(days=day)):
                    updated = _finding("TEST_REPEAT", "service", "warning", service, "Problem", evidence={"days": 20 - day})
                    self.assertEqual(updated.pk, finding.pk)
                    self.assertEqual(updated.first_detected, original)
                    self.assertEqual(dispatch_alerts([rule.pk])["delivered"], 0)
            with patch("netbox_certificates.services.alerts_v1.timezone.now", return_value=original + timedelta(days=8)):
                self.assertEqual(dispatch_alerts([rule.pk])["delivered"], 1)
            rule.repeat_minutes = 0
            rule.save()
            with patch("netbox_certificates.services.alerts_v1.timezone.now", return_value=original + timedelta(days=90)):
                self.assertEqual(dispatch_alerts([rule.pk])["delivered"], 0)
            self.assertEqual(deliver.call_count, 2)
        self.assertEqual(AlertEvent.objects.filter(status="delivered").count(), 2)
