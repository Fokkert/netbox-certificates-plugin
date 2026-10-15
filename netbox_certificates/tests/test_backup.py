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

from netbox_certificates.api.backup import BackupRestoreAPIView
from netbox_certificates.export_v1 import serialize_object
from netbox_certificates.models import ArtifactGroup, Certificate, PrivateKey, Bundle
from netbox_certificates.models_v1 import Service, AlertChannel, AlertRule, AlertSettings, AlertEvent, HealthFinding, ObjectLink
from netbox_certificates.services.health_v1 import _finding, _stable_fingerprint
from netbox_certificates.services.backup import BackupError, CONFIRMATION, create_backup, restore_backup, pack, unpack
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

    def test_full_round_trip_with_new_encryption_key_and_ids(self):
        old_cert = self.populate()
        data = create_backup(self.user, "backup-password")
        self.assertNotIn(b"smtp-secret", data)
        with override_settings(PLUGINS_CONFIG={"netbox_certificates": {"encryption_key": Fernet.generate_key().decode()}}):
            result = restore_backup(data, self.user, CONFIRMATION, "backup-password")
            self.assertGreater(result["restored"], 5)
            self.assertEqual(result["warnings"], [])
            cert = Certificate.objects.get()
            self.assertNotEqual(cert.pk, old_cert.pk)
            self.assertEqual(cert.material, old_cert.material)
            self.assertEqual(cert.groups.get().parent.name, "Root")
            self.assertEqual(Service.objects.get().certificates.get(), cert)
            self.assertEqual(Service.objects.get().bundles.get(), Bundle.objects.get())
            self.assertEqual(decrypt_text(AlertChannel.objects.get().smtp_password_encrypted), "smtp-secret")
            self.assertIn(b"PRIVATE KEY", decrypt_private_key(PrivateKey.objects.get().encrypted_material))
            self.assertEqual(AlertSettings.objects.get().rule.repeat_minutes, 10080)

    def test_wrong_password_confirmation_and_corruption_preserve_data(self):
        self.populate()
        data = create_backup(self.user, "correct")
        for password, confirmation, payload in (("wrong", CONFIRMATION, data), ("correct", "", data), ("correct", CONFIRMATION, data[:-1] + bytes([data[-1] ^ 1]))):
            with self.assertRaises(BackupError):
                restore_backup(payload, self.user, confirmation, password)
            self.assertEqual(Certificate.objects.count(), 1)

    def test_health_history_and_missing_external_tag(self):
        from extras.models import Tag
        cert = self.populate()
        tag = Tag.objects.create(name="Source-only tag", slug="source-only-tag")
        cert.tags.add(tag)
        finding = _finding("BACKUP_TEST", "service", "warning", Service.objects.get(), "Test finding", related=cert)
        AlertEvent.objects.create(finding=finding, rule=AlertRule.objects.get(), channel=AlertChannel.objects.get(), status="delivered")
        data = create_backup(self.user)
        tag.delete()
        result = restore_backup(data, self.user, CONFIRMATION)
        self.assertTrue(result["warnings"])
        finding = HealthFinding.objects.get()
        self.assertEqual(finding.affected_object, Service.objects.get())
        self.assertEqual(finding.related_object, Certificate.objects.get())
        self.assertEqual(finding.fingerprint, _stable_fingerprint("BACKUP_TEST", Service.objects.get(), Certificate.objects.get()))
        self.assertEqual(AlertEvent.objects.get().finding, finding)
        self.assertFalse(Certificate.objects.get().tags.exists())

    def test_mutually_linked_generic_objects(self):
        self.populate()
        service = Service.objects.get()
        cert = Certificate.objects.get()
        a = ObjectLink.objects.create(source=service, target=cert, relationship="related")
        b = ObjectLink.objects.create(source=cert, target=a, relationship="related")
        a.target = b
        a.save()
        restore_backup(create_backup(self.user), self.user, CONFIRMATION)
        ct = ContentType.objects.get_for_model(ObjectLink)
        links = list(ObjectLink.objects.filter(target_type=ct))
        self.assertEqual(len(links), 2)
        self.assertEqual({link.target_object_id for link in links}, {link.pk for link in links})

    def test_invalid_object_rolls_back_deletions(self):
        self.populate()
        document = unpack(create_backup(self.user))
        row = next(row for row in document["objects"] if row["model"].endswith(".service"))
        row["fields"]["port"] = 70000
        original = Certificate.objects.get().pk
        with self.assertRaises(BackupError):
            restore_backup(pack(document), self.user, CONFIRMATION)
        self.assertEqual(Certificate.objects.get().pk, original)
        self.assertEqual(Service.objects.get().port, 443)

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

    def test_permissions_ui_and_api_confirmation(self):
        other = get_user_model().objects.create_user(username="backup-denied")
        with self.assertRaises(PermissionDenied):
            create_backup(other)
        self.client.force_login(other)
        self.assertEqual(self.client.get(reverse("plugins:netbox_certificates:backup")).status_code, 403)
        self.client.force_login(self.user)
        self.assertContains(self.client.get(reverse("plugins:netbox_certificates:backup")), "erases all existing")
        request = APIRequestFactory().post("/backup/restore/", {"upload": SimpleUploadedFile("backup.zip", create_backup(self.user))}, format="multipart")
        force_authenticate(request, user=self.user, token=SimpleNamespace(write_enabled=True))
        response = BackupRestoreAPIView.as_view()(request)
        self.assertEqual(response.status_code, 400)
        request = APIRequestFactory().post("/backup/restore/", {"upload": SimpleUploadedFile("backup.zip", create_backup(self.user)), "confirmation": CONFIRMATION}, format="multipart")
        force_authenticate(request, user=self.user, token=SimpleNamespace(write_enabled=True))
        self.assertEqual(BackupRestoreAPIView.as_view()(request).status_code, 200)
        request = APIRequestFactory().post("/backup/restore/", {}, format="json")
        force_authenticate(request, user=self.user, token=SimpleNamespace(write_enabled=False))
        self.assertEqual(BackupRestoreAPIView.as_view()(request).status_code, 403)
