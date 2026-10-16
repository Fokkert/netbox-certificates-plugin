import json
from types import SimpleNamespace

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.core.serializers.json import DjangoJSONEncoder
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase, override_settings
from django.urls import reverse
from rest_framework.test import APIRequestFactory, force_authenticate

from netbox_certificates.export_v1 import serialize_object
from netbox_certificates.models import ArtifactGroup, Certificate, PrivateKey, Bundle
from netbox_certificates.models_v1 import Service, AlertChannel, AlertRule, AlertSettings, AlertEvent, HealthFinding, ObjectLink
from netbox_certificates.services.health_v1 import _finding, _stable_fingerprint
from netbox_certificates.services.encryption import decrypt_private_key
from netbox_certificates.services.metadata_import import import_metadata
from netbox_certificates.services.secret_v1 import encrypt_text, decrypt_text
from netbox_certificates.services.unified_import import import_objects, UploadItem
from . import test_revision_140


class BackupTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        test_revision_140.Revision140Tests.setUpTestData.__func__(cls)

    def populate(self):
        pem = self.cert.public_bytes(serialization.Encoding.PEM)
        key = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        import_objects(uploads=[UploadItem("server.pem", pem + key)], allowed_kinds={"certificate", "private_key", "csr"}, user=self.user)
        root = ArtifactGroup.objects.create(name="Root", group_type="group")
        group = ArtifactGroup.objects.create(name="Certificates", parent=root, group_type="certificate")
        cert = Certificate.objects.get()
        cert.groups.add(group)
        service = Service.objects.create(name="Web", port=443)
        service.certificates.add(cert)
        service.private_keys.add(PrivateKey.objects.get())
        service.bundles.add(Bundle.objects.get())
        channel = AlertChannel.objects.create(name="SMTP", enabled=False, channel_type="email", smtp_password_encrypted=encrypt_text("smtp-secret"))
        rule = AlertRule.objects.create(name="Weekly", repeat_minutes=10080)
        rule.channels.add(channel)
        rule.services.add(service)
        AlertSettings.objects.update_or_create(pk=1, defaults={"rule": rule, "email_channel": channel})
        return cert






    def test_metadata_merge_portable_and_missing_members(self):
        self.populate()
        cert = Certificate.objects.get()
        group = ArtifactGroup.objects.get(name="Certificates")
        exported = [serialize_object(group, self.user), serialize_object(Service.objects.get(), self.user)]
        group.delete()
        Service.objects.all().delete()
        result = import_metadata(json.dumps(exported, cls=DjangoJSONEncoder).encode(), self.user)
        self.assertEqual(result["imported"], 2)
        self.assertEqual(Service.objects.get().certificates.get(), cert)
        self.assertEqual(ArtifactGroup.objects.get(name="Certificates").certificates.get(), cert)
        Certificate.objects.all().delete()
        result = import_metadata(json.dumps(exported, cls=DjangoJSONEncoder).encode(), self.user)
        self.assertTrue(result["warnings"])
        self.assertFalse(Service.objects.get().certificates.exists())
