"""Real cryptographic parsing/signing, form validation, and bounded import checks."""
import io
import hashlib
import ipaddress
import json
import re
import sys
import tarfile
import tempfile
import types
import unittest
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import PurePosixPath
from types import SimpleNamespace
from unittest.mock import Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from django import forms
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.validators import validate_email
from django.db import transaction
from django.http import FileResponse, JsonResponse
from django.core.serializers.json import DjangoJSONEncoder

from test_revision_behavior import ROOT, definitions


def source_module(name, path, replacements=(), **scope):
    module = types.ModuleType(name)
    module.__dict__.update(scope)
    sys.modules[name] = module
    source = (ROOT / path).read_text(encoding="utf-8")
    for old, new in replacements:
        source = source.replace(old, new)
    exec(compile(source, str(path), "exec"), module.__dict__)
    return module


VALIDATORS = source_module("validation_120", "netbox_certificates/validation.py")
PARSER = source_module("parser_120", "netbox_certificates/services/parser.py",
                       [("from .status import calculate_certificate_status", "")], calculate_certificate_status=lambda *args, **kwargs: "active")
CSR_SERVICE = source_module("csr_120", "netbox_certificates/services/csr.py",
                           [("from ..validation import validate_hostname", "")], validate_hostname=VALIDATORS.validate_hostname)


class ValidationAndSigning(unittest.TestCase):
    def test_explicit_empty_headers_clear_while_blank_preserves(self):
        field = VALIDATORS.OptionalObjectJSONField(required=False)
        self.assertEqual(field.clean("{}"), {})
        self.assertIsNone(field.clean(""))
        for value in ("[]", '"text"', "42", "true"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                field.clean(value)

    def test_port_and_url_boundaries(self):
        for value in (1, 443, 65535):
            VALIDATORS.validate_port(value)
        for value in (-1, 0, 65536, 1.5, True, "443", None):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                VALIDATORS.validate_port(value)
        for value in ("https://example.com:65536", "https://example.com:0", "ftp://example.com", "https://user:password@example.com"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                VALIDATORS.validate_endpoint_url(value, http_only=True)
        VALIDATORS.validate_endpoint_url("https://example.com:65535", http_only=True)

    def test_hostname_and_header_validation(self):
        for value in ("smtp.internal", "localhost", "192.0.2.1", "2001:db8::1"):
            VALIDATORS.validate_hostname(value)
        for value in ("host name", "host:587", "-host", "x..example", "smtp\r\nserver"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                VALIDATORS.validate_hostname(value)
        VALIDATORS.validate_headers({"X-Test": "valid"})
        for value in ([], {"Bad Header": "x"}, {"X-Test": "a\rb"}, {"": "x"}, {"Test": 2}):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                VALIDATORS.validate_headers(value)

    def test_reusing_rsa_and_ec_keys_signs_valid_csr(self):
        for key in (rsa.generate_private_key(public_exponent=65537, key_size=2048), ec.generate_private_key(ec.SECP256R1()), ed25519.Ed25519PrivateKey.generate()):
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
            returned, csr_pem = CSR_SERVICE.generate_csr(common_name="example.com", sans=["DNS:example.com"], private_key_pem=pem)
            csr = x509.load_pem_x509_csr(csr_pem)
            self.assertTrue(csr.is_signature_valid)
            self.assertEqual(PARSER.public_key_fingerprint(csr.public_key()), PARSER.public_key_fingerprint(key.public_key()))
            self.assertEqual(returned, pem)

    def test_invalid_csr_inputs_rejected(self):
        for options in ({"email": "invalid"}, {"country": "1X"}, {"common_name": "x" * 65},
                        {"sans": ["DNS:bad host"]}, {"sans": ["EMAIL:invalid"]}, {"sans": ["IP:999.1.1.1"]},
                        {"sans": ["URI:invalid"]}, {"key_usages": ["unknown"]},
                        {"extended_key_usages": ["unknown"]}, {"path_length": 1}):
            with self.subTest(options=options), self.assertRaises(CSR_SERVICE.CSRGenerationError):
                CSR_SERVICE.generate_csr(**{"common_name": "example.com", **options})

    def test_key_use_permission_checked_before_decryption(self):
        decrypt = Mock()
        model = object
        workflow = definitions("netbox_certificates/services/csr_workflow.py", ["save_generated_csr"],
                               transaction=transaction, CSR=model, require_action_permission=Mock(),
                               object_allowed=lambda *args: False, PermissionDenied=PermissionDenied,
                               decrypt_private_key=decrypt)["save_generated_csr"]
        with self.assertRaises(PermissionDenied):
            workflow({"existing_private_key": object()}, object())
        decrypt.assert_not_called()

    def test_alert_form_rejects_invalid_disabled_destinations_and_check_values(self):
        line_field = definitions("netbox_certificates/forms_v1.py", ["LineListField"], forms=forms)["LineListField"]
        form = definitions("netbox_certificates/alert_settings.py", ["AlertSettingsForm"], forms=forms,
                           LineListField=line_field, FindingSeverityChoices=[("critical", "Critical")],
                           transaction=transaction, validate_email=validate_email)["AlertSettingsForm"]
        base = dict(categories=["validity"], cooldown_minutes=60, repeat_minutes=0, smtp_security="starttls", subject_prefix="Test")
        self.assertTrue(form(base).is_valid())
        for field, value in (("smtp_port", 65536), ("recipients", "not-an-email"), ("from_email", "not-an-email"),
                             ("webhook_url", "ftp://example.com"), ("smtp_host", "host:587"),
                             ("minimum_rsa_bits", 1024), ("max_validity_days", 0), ("webhook_headers", '{"Bad Header": "x"}')):
            instance = form({**base, field: value})
            with self.subTest(field=field):
                self.assertFalse(instance.is_valid())
                self.assertIn(field, instance.errors)


class MixedImportParsing(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.pem = cls.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        cls.csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])).sign(cls.key, hashes.SHA256())
        now = datetime.now(timezone.utc)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example.com")])
        cls.cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(cls.key.public_key())
                    .serial_number(7).not_valid_before(now).not_valid_after(now + timedelta(days=90))
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True).sign(cls.key, hashes.SHA256()))

    def scope(self, limit=10000):
        archive = definitions("netbox_certificates/services/bundles.py", ["BundleImportError", "extract_archive", "is_archive"],
                              MAX_ARCHIVE_FILES=limit, MAX_ARCHIVE_UNCOMPRESSED_BYTES=128 * 1024 * 1024,
                              ArchiveMember=lambda name, data: SimpleNamespace(name=name, data=data),
                              io=io, zipfile=zipfile, tarfile=tarfile, ALLOW_RAR=False)
        scope = definitions("netbox_certificates/services/unified_import.py", ["UnifiedImportError", "parse_uploads", "validate_import_records"],
                            UploadItem=lambda name, data: SimpleNamespace(name=name, data=data), parse_blob=PARSER.parse_blob,
                            ArtifactParseError=PARSER.ArtifactParseError, PurePosixPath=PurePosixPath,
                            MAX_UPLOAD_BYTES=64 * 1024 * 1024, **archive)
        return scope

    @staticmethod
    def archive(files):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in files:
                archive.writestr(name, data)
        return stream.getvalue()

    def test_mixed_nested_archives_and_content_detection(self):
        nested = self.archive([("key.unusual", self.pem), ("request.csr", self.csr.public_bytes(serialization.Encoding.PEM))])
        content = self.archive([("certificate.bin", self.cert.public_bytes(serialization.Encoding.DER)),
                                ("bundle.zip", nested), ("manifest.json", b"{}")])
        records, ignored = self.scope()["parse_uploads"]([SimpleNamespace(name="inventory.zip", data=content)])
        self.assertEqual({parsed.kind for _, parsed in records}, {"certificate", "private_key", "csr"})
        self.assertEqual(len({obj.metadata["public_key_fingerprint"] for _, obj in records}), 1)
        self.assertEqual(ignored, ["manifest.json"])

    def test_more_than_thousand_archive_members(self):
        content = self.archive([(f"{index}.crt", self.cert.public_bytes(serialization.Encoding.PEM)) for index in range(1001)])
        records, _ = self.scope()["parse_uploads"]([SimpleNamespace(name="batch.zip", data=content)])
        self.assertEqual(len(records), 1001)

    def test_pfx_and_mixed_pem_detect_all_members(self):
        pfx = pkcs12.serialize_key_and_certificates(b"example", self.key, self.cert, None, serialization.BestAvailableEncryption(b"secret"))
        records, _ = self.scope()["parse_uploads"]([SimpleNamespace(name="container.dat", data=pfx)], password="secret")
        self.assertEqual({parsed.kind for _, parsed in records}, {"certificate", "private_key"})
        mixed = self.pem + self.cert.public_bytes(serialization.Encoding.PEM) + self.csr.public_bytes(serialization.Encoding.PEM)
        records, _ = self.scope()["parse_uploads"]([SimpleNamespace(name="all.pem", data=mixed)])
        self.assertEqual(len(records), 3)

    def test_invalid_member_and_path_reject_entire_input(self):
        for filename, payload in (("bad.crt", b"not a certificate"), ("bad.bin", b"invalid"), ("../bad.key", self.pem)):
            content = self.archive([("good.crt", self.cert.public_bytes(serialization.Encoding.PEM)), (filename, payload)])
            scope = self.scope()
            with self.subTest(filename=filename), self.assertRaises(scope["UnifiedImportError"]):
                scope["parse_uploads"]([SimpleNamespace(name="batch.zip", data=content)])

    def test_count_limit_and_metadata_only_archive_rejected(self):
        for content in (self.archive([(f"{i}.crt", b"data") for i in range(4)]), self.archive([("manifest.json", b"{}")])):
            scope = self.scope(limit=3)
            with self.assertRaises(scope["UnifiedImportError"]):
                scope["parse_uploads"]([SimpleNamespace(name="batch.zip", data=content)])

    def test_invalid_csr_signature_is_rejected(self):
        data = bytearray(self.csr.public_bytes(serialization.Encoding.DER))
        data[-1] ^= 1
        with self.assertRaises(PARSER.ArtifactParseError):
            PARSER.parse_blob(bytes(data), filename="broken.csr")

    def test_inventory_zip_contains_reimportable_material_and_valid_checksums(self):
        class Artifact:
            def __init__(self, **values):
                self.__dict__.update(values)

            def __str__(self):
                return self.name

        class Query(list):
            def order_by(self, *args):
                return self

            def exists(self):
                return bool(self)

            def iterator(self, **kwargs):
                return iter(self)

        certificate, private_key, csr = (type(name, (Artifact,), {}) for name in ("Certificate", "PrivateKey", "CSR"))
        objects = {}
        for model, kind, data in (
            (certificate, "certificate", self.cert.public_bytes(serialization.Encoding.PEM)),
            (private_key, "privatekey", self.pem),
            (csr, "csr", self.csr.public_bytes(serialization.Encoding.PEM)),
        ):
            objects[model] = Query([model(pk=1, name="example.com", material=data.decode("ascii"), encrypted_material=data,
                                          fingerprint_sha256=hashlib.sha256(data).hexdigest(),
                                          public_key_fingerprint=PARSER.public_key_fingerprint(self.key.public_key()),
                                          _meta=SimpleNamespace(model_name=kind, label_lower=f"netbox_certificates.{kind}"))])
        # Distinct rows with identical fingerprints must still have unique ZIP paths.
        objects[certificate].append(certificate(**{**objects[certificate][0].__dict__, "pk": 2}))
        export = definitions("netbox_certificates/bulk_export.py", ["_artifact_token", "_artifact_filename", "_write_member",
                              "_material_for_object", "_object_manifest", "_secure_file_response"],
                             Certificate=certificate, PrivateKey=private_key, CSR=csr,
                             decrypt_private_key=lambda data: data, zipfile=zipfile, hashlib=hashlib, FileResponse=FileResponse)
        permission = Mock()
        inventory = definitions("netbox_certificates/inventory_export.py", ["export_inventory"], **export,
                                EXPORT_CONFIG={kind: {"model": model, "action": "download"} for kind, model in
                                               (("certificate", certificate), ("privatekey", private_key), ("csr", csr))},
                                CONFIG={}, require_action_permission=permission,
                                action_queryset=lambda model, user, action: objects[model], tempfile=tempfile,
                                json=json, DjangoJSONEncoder=DjangoJSONEncoder, PermissionDenied=PermissionDenied)
        response = inventory["export_inventory"](SimpleNamespace(user=SimpleNamespace(is_superuser=True)),
                                                 ["certificate", "privatekey", "csr"])
        try:
            content = b"".join(response.streaming_content)
        finally:
            response.close()
        self.assertEqual(permission.call_count, 3)
        with zipfile.ZipFile(io.BytesIO(content)) as archive:
            self.assertEqual(len(archive.namelist()), len(set(archive.namelist())))
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest["count"], 4)
            for entry in manifest["files"]:
                self.assertEqual(hashlib.sha256(archive.read(entry["path"])).hexdigest(), entry["sha256"])
        records, ignored = self.scope()["parse_uploads"]([SimpleNamespace(name="inventory.zip", data=content)])
        self.assertEqual({parsed.kind for _, parsed in records}, {"certificate", "private_key", "csr"})
        self.assertEqual(len({obj.metadata["public_key_fingerprint"] for _, obj in records}), 1)
        self.assertEqual(ignored, ["manifest.json"])


class NewReleaseContracts(unittest.TestCase):
    def test_retired_policy_endpoints_and_private_key_permission(self):
        routes = (ROOT / "netbox_certificates/api/v1_urls.py").read_text(encoding="utf-8")
        self.assertNotIn('router.register("certificate-policies"', routes)
        models = (ROOT / "netbox_certificates/models.py").read_text(encoding="utf-8")
        self.assertIn('"use_privatekey"', models)
        urls = (ROOT / "netbox_certificates/urls.py").read_text(encoding="utf-8")
        self.assertIn('RetiredPolicyView.as_view()', urls)
        self.assertIn('name="inventory_export"', urls)

    def test_ui_empty_export_is_a_warning_page_without_redirect(self):
        render = Mock(return_value="warning-page")
        scope = definitions("netbox_certificates/empty_exports.py", ["empty_export_response"], render=render, JsonResponse=JsonResponse)
        self.assertEqual(scope["empty_export_response"](object()), "warning-page")
        self.assertEqual(render.call_args.args[1], "netbox_certificates/empty_export.html")
        self.assertIn("no objects", render.call_args.args[2]["warning"])
