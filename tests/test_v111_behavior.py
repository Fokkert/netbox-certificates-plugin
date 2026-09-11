"""Regressions for v1.1.1 without a running NetBox/PostgreSQL/Redis stack."""
import calendar
from collections import defaultdict
from datetime import datetime, timedelta, timezone as dt_timezone
import hashlib
import io
import json
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock
from unittest.mock import patch
import sys
from types import ModuleType
import zipfile

import django
import django_filters
from django import forms
from django.core.exceptions import PermissionDenied
from django.core.serializers.json import DjangoJSONEncoder
from django.core.validators import validate_email
from django.db import connection, models, transaction
from django.http import FileResponse, Http404, HttpResponse, JsonResponse, QueryDict
from django.utils import timezone
from django.views import View
from rest_framework import serializers
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from test_revision_behavior import ROOT, definitions

django.setup()

# Authentication itself is NetBox integration behavior; these tests call GET directly.
class LoginRequiredMixin:
    pass


class Group(models.Model):
    name = models.CharField(max_length=100)
    parent = models.ForeignKey("self", null=True, on_delete=models.SET_NULL)

    class Meta:
        app_label = "revision_tests"

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return f"/groups/{self.pk}/"


class InventoryFilter(django_filters.FilterSet):
    q = django_filters.CharFilter(field_name="name", lookup_expr="icontains")
    id = django_filters.NumberFilter()

    class Meta:
        model = Group
        fields = ["q", "id"]


class EmptyExportsAndGroups(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with connection.schema_editor() as editor:
            editor.create_model(Group)

    @classmethod
    def tearDownClass(cls):
        with connection.schema_editor() as editor:
            editor.delete_model(Group)

    def setUp(self):
        Group.objects.all().delete()
        self.request = SimpleNamespace(GET=QueryDict(), user=SimpleNamespace(is_superuser=True))

    def bulk_scope(self):
        return definitions("netbox_certificates/bulk_export.py",
                           ["_filtered_query_data", "apply_current_filters", "_write_member", "_secure_file_response", "BulkMaterialExportView"],
                           LoginRequiredMixin=LoginRequiredMixin, View=View, QueryDict=QueryDict,
                           Http404=Http404, HttpResponse=HttpResponse, FileResponse=FileResponse,
                           require_action_permission=Mock(), action_queryset=lambda *args: Group.objects.none(),
                           EXPORT_CONFIG={"certificate": {"model": Group, "action": "download", "filterset": InventoryFilter, "filename": "certificates.zip"}},
                           tempfile=tempfile, zipfile=zipfile, hashlib=hashlib, datetime=datetime, timezone=dt_timezone,
                           json=json, PrivateKeyEncryptionError=RuntimeError)

    def test_empty_material_export_returns_manifest(self):
        scope = self.bulk_scope()
        response = scope["BulkMaterialExportView"]().get(self.request, "certificate")
        self.assertEqual(response.status_code, 200)
        archive = zipfile.ZipFile(io.BytesIO(b"".join(response.streaming_content)))
        response.close()
        manifest = json.loads(archive.read("manifest.json"))
        self.assertEqual((manifest["count"], manifest["objects"], manifest["files"]), (0, [], []))

    def test_empty_metadata_export_returns_empty_object_array(self):
        scope = definitions("netbox_certificates/export_v1.py", ["_filtered_data", "_write", "MetadataArchiveExportView"],
                            LoginRequiredMixin=LoginRequiredMixin, View=View, QueryDict=QueryDict, Http404=Http404,
                            JsonResponse=JsonResponse, FileResponse=FileResponse, tempfile=tempfile, zipfile=zipfile,
                            hashlib=hashlib, datetime=datetime, timezone=dt_timezone, json=json, DjangoJSONEncoder=DjangoJSONEncoder,
                            require_action_permission=Mock(), action_queryset=lambda *args: Group.objects.none(), serialize_object=Mock(),
                            CONFIG={"healthfinding": (Group, InventoryFilter, "archive_export", "health.zip")})
        response = scope["MetadataArchiveExportView"]().get(self.request, "healthfinding")
        self.assertEqual(response.status_code, 200)
        archive = zipfile.ZipFile(io.BytesIO(b"".join(response.streaming_content)))
        response.close()
        self.assertEqual(json.loads(archive.read("objects.json")), [])
        self.assertEqual(json.loads(archive.read("manifest.json"))["count"], 0)

    def test_empty_query_and_display_options_preserve_results(self):
        Group.objects.create(name="kept")
        scope = self.bulk_scope()
        for query in ("", "sort=name&page=2&columns=name"):
            self.request.GET = QueryDict(query)
            qs, errors, _ = scope["apply_current_filters"](InventoryFilter, self.request, Group.objects.all())
            self.assertIsNone(errors)
            self.assertEqual(list(qs.values_list("name", flat=True)), ["kept"])

    def test_invalid_filter_has_a_readable_field_error(self):
        self.request.GET = QueryDict("id=invalid")
        response = self.bulk_scope()["BulkMaterialExportView"]().get(self.request, "certificate")
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"id", response.content)
        self.assertIn(b"Enter a number", response.content)

    def test_created_groups_are_visible_without_filters_and_keep_hierarchy(self):
        parent = Group.objects.create(name="Parent")
        child = Group.objects.create(name="Child", parent=parent)
        empty = Mock()
        empty.filter.return_value.values.return_value.distinct.return_value.order_by.return_value = []
        cls = definitions("netbox_certificates/views_v1.py", ["ArtifactGroupTreeListView"],
                          LoginRequiredMixin=LoginRequiredMixin, View=View, ArtifactGroup=Group,
                          ArtifactGroupV1FilterSet=InventoryFilter, ArtifactGroupV1FilterForm=object,
                          Certificate=Group, PrivateKey=Group, CSR=Group, Bundle=Group, Service=Group,
                          defaultdict=defaultdict, action_queryset=lambda *args: empty)["ArtifactGroupTreeListView"]
        result = cls().get_extra_context(self.request)
        self.assertEqual(result["group_tree"][0]["id"], parent.pk)
        self.assertEqual(result["group_tree"][0]["children"][0]["id"], child.pk)
        self.request.GET = QueryDict("q=Child")
        self.assertEqual(cls().get_extra_context(self.request)["group_tree"][0]["id"], child.pk)


class CertificateTiming(unittest.TestCase):
    def scope(self):
        return definitions("netbox_certificates/services/expiry.py", ["_replace_day_safely", "alert_trigger_at", "certificate_alert_due"],
                           calendar=calendar, timedelta=timedelta, timezone=timezone)

    def test_calendar_month_and_exact_trigger_boundary(self):
        expiry = datetime(2028, 3, 31, 12, tzinfo=dt_timezone.utc)
        cert = SimpleNamespace(valid_to=expiry, trigger_unit="month", alert_trigger=1)
        due = self.scope()["certificate_alert_due"]
        self.assertFalse(due(cert, datetime(2028, 2, 29, 11, 59, tzinfo=dt_timezone.utc)))
        self.assertTrue(due(cert, datetime(2028, 2, 29, 12, tzinfo=dt_timezone.utc)))
        cert.alert_trigger = None
        cert.trigger_unit = ""
        self.assertFalse(due(cert, expiry+timedelta(days=1)))

    def test_extreme_lead_times_do_not_crash_scans(self):
        expiry = datetime(2028, 3, 31, tzinfo=dt_timezone.utc)
        for unit in ("year", "month", "week", "day", "hour", "minute", "second"):
            trigger = self.scope()["alert_trigger_at"](expiry, unit, 2147483647)
            self.assertLess(trigger, expiry)

    def test_expiration_alerts_use_certificate_timing_even_with_legacy_rule_threshold(self):
        manager = SimpleNamespace(exists=lambda: False)
        rule = SimpleNamespace(finding_codes=[], categories=[], severities=[], statuses=[], object_types=[], owner_ids=[],
                               tag_names=[], expiration_days=1, services=manager, groups=manager, policies=manager)
        cert = SimpleNamespace(valid_to=timezone.now()+timedelta(days=20), trigger_unit="month", alert_trigger=1)
        finding = SimpleNamespace(code="CERT_EXPIRING", status="active", affected_object=cert)
        match = definitions("netbox_certificates/services/alerts_v1.py", ["_matches"],
                            FindingStatusChoices=SimpleNamespace(RESOLVED="resolved"),
                            certificate_alert_due=self.scope()["certificate_alert_due"])["_matches"]
        self.assertTrue(match(rule, finding))
        cert.trigger_unit = "day"
        cert.alert_trigger = 7
        self.assertFalse(match(rule, finding))


class CAValidation(unittest.TestCase):
    def test_ca_flag_is_derived_from_real_x509_basic_constraints(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "import-test")])
        parser = definitions("netbox_certificates/services/parser.py",
                             ["_certificate_parsed", "_sans", "_name_from_x509_name", "_key_metadata", "public_key_fingerprint", "sha256_hex"],
                             x509=x509, serialization=serialization, hashes=hashes, hashlib=hashlib,
                             ParsedArtifact=lambda kind, data, fmt, name, metadata: SimpleNamespace(kind=kind, metadata=metadata),
                             calculate_certificate_status=lambda *args: "active")
        validation = definitions("netbox_certificates/services/unified_import.py", ["UnifiedImportError", "validate_import_records"])
        for ca in (True, False, None):
            builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                       .serial_number(x509.random_serial_number()).not_valid_before(timezone.now()-timedelta(days=1))
                       .not_valid_after(timezone.now()+timedelta(days=365)))
            if ca is not None:
                builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
            parsed = parser["_certificate_parsed"](builder.sign(key, hashes.SHA256()), "pem")
            self.assertEqual(parsed.metadata["is_ca"], ca is True)
            if ca is True:
                validation["validate_import_records"]([("ca.pem", parsed)], {"certificate"}, ca_only=True)
            else:
                with self.assertRaises(validation["UnifiedImportError"]):
                    validation["validate_import_records"]([("leaf.pem", parsed)], {"certificate"}, ca_only=True)

    def test_ca_only_validation_rejects_leaf_missing_constraints_keys_and_mixed_input(self):
        scope = definitions("netbox_certificates/services/unified_import.py", ["UnifiedImportError", "validate_import_records"])
        valid = SimpleNamespace(kind="certificate", metadata={"is_ca": True})
        invalid = [SimpleNamespace(kind="certificate", metadata={"is_ca": False}),
                   SimpleNamespace(kind="certificate", metadata={}), SimpleNamespace(kind="private_key", metadata={}),
                   SimpleNamespace(kind="csr", metadata={})]
        scope["validate_import_records"]([("ca.pem", valid)], {"certificate"}, ca_only=True)
        for artifact in invalid:
            with self.assertRaisesRegex(scope["UnifiedImportError"], "only CA certificates"):
                scope["validate_import_records"]([("ca.pem", valid), ("bad.pem", artifact)], {"certificate", "private_key", "csr"}, ca_only=True)

    def test_ca_api_rejects_non_ca_even_when_client_claims_ca(self):
        class ParsedCertificateSerializer(serializers.Serializer):
            material = serializers.CharField()
            is_ca = serializers.BooleanField(read_only=True)

            def validate(self, attrs):
                attrs["is_ca"] = attrs["material"] == "CA parsed from X.509"
                return attrs

        cls = definitions("netbox_certificates/api/v1_serializers.py", ["CACertificateSerializer"],
                          CertificateSerializer=ParsedCertificateSerializer, serializers=serializers)["CACertificateSerializer"]
        self.assertFalse(cls(data={"material": "leaf", "is_ca": True}).is_valid())
        self.assertTrue(cls(data={"material": "CA parsed from X.509"}).is_valid())


class PermissionsAndSettings(unittest.TestCase):
    def test_reused_ca_requires_change_permission_only_for_new_memberships(self):
        check = definitions("netbox_certificates/services/importing.py", ["_check_reused_group_permissions"],
                            object_allowed=lambda *args: False, PermissionDenied=PermissionDenied)["_check_reused_group_permissions"]
        certificate = SimpleNamespace(groups=SimpleNamespace(values_list=lambda *args, **kwargs: [1]))
        check([certificate], [SimpleNamespace(pk=1)], object())
        with self.assertRaises(PermissionDenied):
            check([certificate], [SimpleNamespace(pk=2)], object())

    def test_status_permission_is_checked_before_netbox_mutates_instance(self):
        class MutatingSerializer(serializers.Serializer):
            status = serializers.ChoiceField(choices=["active", "ignored"])

            def validate(self, attrs):
                self.instance.status = attrs["status"]
                return attrs

        cls = definitions("netbox_certificates/api/v1_serializers.py", ["HealthFindingSerializer"],
                          PrimaryModelSerializer=MutatingSerializer, VisibleRelationshipsMixin=type("Mixin", (), {}),
                          HealthFinding=object, serializers=serializers, object_allowed=lambda *args: False)["HealthFindingSerializer"]
        instance = SimpleNamespace(status="active")
        serializer = cls(instance, data={"status": "ignored"}, context={"request": SimpleNamespace(user=object())})
        self.assertFalse(serializer.is_valid())
        self.assertIn("status", serializer.errors)
        self.assertEqual(instance.status, "active")

    def test_channel_api_converts_secrets_before_model_validation(self):
        class ModelValidator(serializers.Serializer):
            channel_type = serializers.CharField()

            def validate(self, attrs):
                if any(name in attrs for name in ("smtp_password", "webhook_url", "webhook_headers")):
                    raise TypeError("Unexpected model constructor field")
                return attrs

        cls = definitions("netbox_certificates/api/v1_serializers.py", ["AlertChannelSerializer"],
                          PrimaryModelSerializer=ModelValidator, VisibleRelationshipsMixin=type("Mixin", (), {}),
                          AlertChannel=object, serializers=serializers, transaction=transaction,
                          SecretConfigurationError=RuntimeError, encrypt_text=lambda text: "encrypted:"+text,
                          encrypt_json=lambda value: "encrypted:"+json.dumps(value))["AlertChannelSerializer"]
        serializer = cls(data={"channel_type": "webhook", "webhook_url": "https://example.com/test",
                               "webhook_headers": {"X-Test": "sample"}})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertTrue(serializer.validated_data["webhook_url_encrypted"].startswith("encrypted:"))

    def test_sample_tests_send_payload_and_honor_tls_choice(self):
        secret = ModuleType("netbox_certificates.services.secret_v1")
        secret.decrypt_text = lambda value: "https://example.com/test"
        secret.decrypt_json = lambda value: {"X-Test": "sample"}
        post = Mock()
        post.return_value.status_code = 200
        email = Mock()
        scope = definitions("netbox_certificates/services/alerts_v1.py", ["send_test_channel"],
                            __package__="netbox_certificates.services", timezone=timezone, json=json, _send_email=email,
                            requests=SimpleNamespace(post=post), AlertChannelTypeChoices=SimpleNamespace(EMAIL="email", WEBHOOK="webhook"))
        channel = SimpleNamespace(name="sample", channel_type="email", subject_prefix="Test")
        payload = scope["send_test_channel"](channel)
        self.assertEqual(json.loads(email.call_args.args[2]), payload)
        channel.channel_type = "webhook"
        channel.webhook_url_encrypted = "ciphertext"
        channel.webhook_headers_encrypted = "ciphertext"
        channel.webhook_verify_tls = False
        with patch.dict(sys.modules, {secret.__name__: secret}):
            scope["send_test_channel"](channel)
        self.assertFalse(post.call_args.kwargs["verify"])
        self.assertFalse(post.call_args.kwargs["allow_redirects"])
        self.assertEqual(post.call_args.kwargs["json"]["type"], "netbox-certificates-alert-test")

    def test_blank_bulk_trigger_choice_does_not_change_timing(self):
        import ast
        tree = ast.parse((ROOT/"netbox_certificates/forms.py").read_text(encoding="utf-8"))
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "CertificateBulkEditForm")
        field = next(node.value for node in cls.body if isinstance(node, ast.Assign) and node.targets[0].id == "trigger_unit")
        expression = ast.Expression(field)
        result = eval(compile(expression, "bulk_trigger", "eval"), {"forms": forms,
                      "AlertTriggerUnitChoices": [("year", "Year"), ("month", "Month")],
                      "add_blank_choice": lambda choices: [("", "---------"), *choices]})
        self.assertEqual(list(result.choices)[0][0], "")
        self.assertEqual(result.clean(""), "")

    def test_custom_action_applies_both_action_and_view_constraints(self):
        queryset = Mock()
        queryset.restrict.return_value = queryset
        model = SimpleNamespace(_meta=SimpleNamespace(model_name="certificate", app_label="netbox_certificates"),
                                objects=SimpleNamespace(all=lambda: queryset))
        user = SimpleNamespace(is_authenticated=True, is_superuser=False, has_perm=lambda name: True)
        scope = definitions("netbox_certificates/permissions.py", ["permission_name", "action_queryset", "require_action_permission"],
                            STANDARD_ACTIONS={"view", "add", "change", "delete"}, PermissionDenied=PermissionDenied)
        scope["action_queryset"](model, user, "download")
        self.assertEqual([call.args[1] for call in queryset.restrict.call_args_list], ["download", "view"])
        user.has_perm = lambda name: False
        with self.assertRaises(PermissionDenied):
            scope["require_action_permission"](model, user, "download")

    def form_class(self):
        line_field = definitions("netbox_certificates/forms_v1.py", ["LineListField"], forms=forms)["LineListField"]
        return definitions("netbox_certificates/alert_settings.py", ["AlertSettingsForm"], forms=forms,
                           LineListField=line_field, FindingSeverityChoices=[("critical", "Critical")],
                           transaction=transaction, validate_email=validate_email)["AlertSettingsForm"]

    def test_disabled_email_can_be_tested_but_requires_destination(self):
        cls = self.form_class()
        base = dict(categories=["validity"], cooldown_minutes=60, repeat_minutes=0, smtp_security="starttls", subject_prefix="Test")
        self.assertTrue(cls(base).is_valid())
        self.assertFalse(cls(base, test_method="email").is_valid())
        base.update(recipients="test@example.com", smtp_host="smtp.example.com", smtp_port=587, from_email="netbox@example.com")
        form = cls(base, test_method="email")
        self.assertTrue(form.is_valid(), form.errors)
        self.assertFalse(form.cleaned_data["email_enabled"])
        self.assertNotIn("expiration_days", form.fields)

    def test_settings_api_defaults_patch_and_secret_redaction(self):
        cls = definitions("netbox_certificates/api/alert_settings.py", ["AlertSettingsSerializer"], serializers=serializers,
                          forms=forms, AlertSettingsForm=self.form_class(), SECRET_FIELDS={"smtp_password", "webhook_url", "webhook_headers"})["AlertSettingsSerializer"]
        serializer = cls(data={"smtp_host": "smtp.example.com"}, context={"config": None})
        self.assertTrue(serializer.is_valid(), serializer.errors)
        self.assertEqual(serializer.form.cleaned_data["repeat_minutes"], 1440)
        output = cls().to_representation(None)
        for secret in ("smtp_password", "webhook_url", "webhook_headers"):
            self.assertNotIn(secret, output)
            self.assertTrue(cls().fields[secret].write_only)

    def test_acronym_labels_preserve_api_identifiers(self):
        scope = definitions("netbox_certificates/labels.py", ["display_label"],
                            _ACRONYMS=re.compile(r"\b(csrs?|ssl|urls?|smtp|sni|ca)\b", re.I))
        self.assertEqual(scope["display_label"]("Csrs / Csr / Ssl / url / Smtp / Sni / Ca"), "CSRS / CSR / SSL / URL / SMTP / SNI / CA")
