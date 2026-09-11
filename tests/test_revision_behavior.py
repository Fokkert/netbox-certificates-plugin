"""Isolated behavior tests using real Django forms and cryptography.

Extract only the named definitions to avoid importing NetBox's PostgreSQL/Redis
application during standalone tests. NetBox integration tests are separate.
"""
import ast
from datetime import datetime, timedelta, timezone as dt_timezone
import importlib.util
import json
import ssl
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import Mock

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from django import forms
from django.conf import settings
from django.core.validators import validate_email
from django.db import transaction
from django.utils import timezone

if not settings.configured:
    settings.configure(USE_I18N=False, SECRET_KEY="isolated-test-only", USE_TZ=True)

ROOT = Path(__file__).resolve().parents[1]


def definitions(path, names, **scope):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    assert {node.name for node in nodes} == set(names), "Missing tested definition"
    exec(compile(ast.Module(body=nodes, type_ignores=[]), str(path), "exec"), scope)
    return scope


class ExportBehavior(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scope = definitions("netbox_certificates/services/pkcs12_export.py", ["PFXExportError", "build_pfx"],
                                x509=x509, serialization=serialization, pkcs12=pkcs12, decrypt_private_key=lambda v: v)
        cls.form = definitions("netbox_certificates/forms.py", ["BundleExportForm"], forms=forms)["BundleExportForm"]
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.cert = cls.certificate(cls.key, "leaf")
        cls.ca = cls.certificate(cls.other_key, "issuer")

    @staticmethod
    def certificate(key, name):
        subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, name)])
        now = datetime.now(dt_timezone.utc)
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=30)).sign(key, hashes.SHA256()))

    def bundle(self, key=None):
        key = key or self.key
        return SimpleNamespace(certificate=SimpleNamespace(name="leaf", material=self.cert.public_bytes(serialization.Encoding.PEM).decode()),
                               private_key=SimpleNamespace(encrypted_material=key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())))

    def test_password_protection_and_chain_round_trip(self):
        ca = SimpleNamespace(material=self.ca.public_bytes(serialization.Encoding.PEM).decode())
        data = self.scope["build_pfx"](self.bundle(), "chosen password", [ca])
        key, cert, chain = pkcs12.load_key_and_certificates(data, b"chosen password")
        self.assertIsNotNone(key)
        self.assertEqual(cert.serial_number, self.cert.serial_number)
        self.assertEqual([c.serial_number for c in chain], [self.ca.serial_number])
        with self.assertRaises(ValueError):
            pkcs12.load_key_and_certificates(data, b"wrong")

    def test_unencrypted_pfx_requires_explicit_opt_in(self):
        with self.assertRaises(self.scope["PFXExportError"]):
            self.scope["build_pfx"](self.bundle(), "")
        data = self.scope["build_pfx"](self.bundle(), "", allow_unencrypted=True)
        key, cert, chain = pkcs12.load_key_and_certificates(data, None)
        self.assertIsNotNone(key)
        self.assertEqual(chain, [])

    def test_mismatched_key_is_rejected(self):
        with self.assertRaisesRegex(self.scope["PFXExportError"], "do not match"):
            self.scope["build_pfx"](self.bundle(self.other_key), "password")

    def test_form_requires_matching_password_only_when_protection_selected(self):
        base = {"archive_format": "zip", "export_pfx": "on"}
        self.assertTrue(self.form(base).is_valid())
        form = self.form({**base, "protect_pfx": "on"})
        self.assertFalse(form.is_valid())
        form = self.form({**base, "protect_pfx": "on", "pfx_password": "abc", "pfx_password_confirm": "xyz"})
        self.assertFalse(form.is_valid())
        self.assertIn("pfx_password_confirm", form.errors)
        self.assertTrue(self.form({"archive_format": "tar", "include_chain": "on"}).is_valid())

    def test_bundle_member_options_exclude_plaintext_key_and_chain(self):
        decrypt = Mock(return_value=b"private-key")
        pfx = Mock(return_value=b"pfx")
        ca = SimpleNamespace(pk=2, name="ca", material="CA")
        bundle = SimpleNamespace(certificate=SimpleNamespace(pk=1, name="leaf", material="CERT"),
                                 private_key=SimpleNamespace(name="key", encrypted_material=b"encrypted"),
                                 csr=None, chain_certificates=SimpleNamespace(all=lambda: [ca]))
        scope = definitions("netbox_certificates/bulk_export.py", ["_bundle_members", "_bundle_chain"],
                            _artifact_token=lambda o: "test", _artifact_filename=lambda o, ext: o.name+ext,
                            decrypt_private_key=decrypt, ordered_chain=lambda c: [ca], build_pfx=pfx)
        members = scope["_bundle_members"](bundle, include_chain=False)
        self.assertEqual([name for name, _, _ in members], ["bundle-test/leaf.crt", "bundle-test/key.key"])
        members = scope["_bundle_members"](bundle, include_chain=True)
        self.assertEqual(len(members), 3)  # automatic and explicit chain membership is deduplicated
        decrypt.reset_mock()
        members = scope["_bundle_members"](bundle, export_pfx=True, protect_pfx=False, include_chain=False)
        self.assertEqual([name for name, _, _ in members], ["bundle-test/bundle-test.pfx"])
        decrypt.assert_not_called()
        pfx.assert_called_once_with(bundle, "", [], allow_unencrypted=True)


class ServiceBehavior(unittest.TestCase):
    def form(self, data):
        from urllib.parse import urlsplit
        source = ast.parse((ROOT / "netbox_certificates/forms_v1.py").read_text())
        service = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == "ServiceForm")
        clean = next(n for n in service.body if isinstance(n, ast.FunctionDef) and n.name == "clean")
        base = type("EndpointForm", (forms.Form,), {
            "deployment": forms.CharField(), "custom_deployment": forms.CharField(required=False),
            "primary_url": forms.CharField(required=False), "hostname": forms.CharField(required=False),
            "sni_name": forms.CharField(required=False), "port": forms.IntegerField(required=False),
            "protocol": forms.CharField(), "deployment_metadata": forms.JSONField(required=False),
        })
        cls = ast.ClassDef(name="ServiceForm", bases=[ast.Name(id="EndpointForm", ctx=ast.Load())], keywords=[], body=[clean], decorator_list=[])
        tree = ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[]))
        scope = {"EndpointForm": base, "urlsplit": urlsplit}
        exec(compile(tree, "ServiceForm.clean", "exec"), scope)
        return scope["ServiceForm"](data)

    def test_endpoint_defaults_and_explicit_overrides(self):
        base = dict(deployment="Nginx", protocol="https", primary_url="https://example.test:8443/")
        form = self.form(base)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual((form.cleaned_data["hostname"], form.cleaned_data["sni_name"], form.cleaned_data["port"]),
                         ("example.test", "example.test", 8443))
        explicit = self.form({**base, "hostname": "alternate.test", "sni_name": "sni.test", "port": 9443})
        self.assertTrue(explicit.is_valid())
        self.assertEqual(explicit.cleaned_data["port"], 9443)
        self.assertEqual(explicit.cleaned_data["sni_name"], "sni.test")
        ldaps = self.form(dict(deployment="Generic TLS Endpoint", protocol="ldaps"))
        self.assertTrue(ldaps.is_valid())
        self.assertEqual(ldaps.cleaned_data["port"], 636)

    def test_custom_deployment_requires_a_name(self):
        form = self.form(dict(deployment="custom", protocol="tls"))
        self.assertFalse(form.is_valid())
        form = self.form(dict(deployment="custom", custom_deployment="Internal appliance", protocol="tls"))
        self.assertTrue(form.is_valid())
        self.assertEqual(form.cleaned_data["deployment"], "Internal appliance")


class HealthBehavior(unittest.TestCase):
    def test_real_model_validity_and_san_fields_are_used(self):
        scope = definitions("netbox_certificates/services/health_v1.py", ["_value", "_validity", "_certificate_sans"])
        start, end = datetime.now(dt_timezone.utc), datetime.now(dt_timezone.utc) + timedelta(days=3)
        cert = SimpleNamespace(valid_from=start, valid_to=end, subject_alternative_names=["DNS:example.test"])
        self.assertEqual(scope["_validity"](cert), (start, end))
        self.assertEqual(scope["_certificate_sans"](cert), ["DNS:example.test"])

    def test_expired_and_expiring_findings_are_generated(self):
        scope = definitions("netbox_certificates/services/health_v1.py", ["_value", "_validity", "_certificate_findings"],
                            timedelta=timedelta, FindingSeverityChoices=SimpleNamespace(CRITICAL="critical", HIGH="high", WARNING="warning", MEDIUM="medium", INFO="info"),
                            _key_type=lambda o: "RSA", _key_bits=lambda o: 2048, _key_curve=lambda o: "", _weak_curve=lambda c: False,
                            _finding=Mock(), _verify_parent_signature=lambda o: None)
        now = datetime.now(dt_timezone.utc)
        cert = SimpleNamespace(pk=1, valid_from=now-timedelta(days=20), valid_to=now-timedelta(days=1),
                               subject="CN=test", issuer="CN=test", is_ca=True)
        scope["_certificate_findings"](cert, now)
        self.assertIn("CERT_EXPIRED", [c.args[0] for c in scope["_finding"].call_args_list])
        scope["_finding"].reset_mock()
        cert.valid_to = now + timedelta(days=10)
        scope["_certificate_findings"](cert, now)
        self.assertIn("CERT_EXPIRING", [c.args[0] for c in scope["_finding"].call_args_list])


class AlertBehavior(unittest.TestCase):
    def test_smtp_tls_verification_is_secure_by_default_and_configurable(self):
        scope = definitions("netbox_certificates/services/smtp.py", ["ConfigurableTLSBackend"],
                            ssl=__import__("ssl"), EmailBackend=__import__("django.core.mail.backends.smtp", fromlist=["EmailBackend"]).EmailBackend,
                            cached_property=__import__("django.utils.functional", fromlist=["cached_property"]).cached_property)
        backend = scope["ConfigurableTLSBackend"]
        self.assertTrue(backend().ssl_context.check_hostname)
        self.assertFalse(backend(verify_tls=False).ssl_context.check_hostname)
        self.assertEqual(backend(verify_tls=False).ssl_context.verify_mode, __import__("ssl").CERT_NONE)

    def test_repeat_zero_sends_once_and_recovery_is_separate(self):
        events = Mock()
        events.filter.return_value = events
        events.exclude.return_value = events
        events.order_by.return_value = events
        events.first.return_value = SimpleNamespace(created=timezone.now()-timedelta(days=10))
        events.exists.return_value = True
        scope = definitions("netbox_certificates/services/alerts_v1.py", ["_recent_event"],
                            AlertEvent=SimpleNamespace(objects=events), AlertEventStatusChoices=SimpleNamespace(DELIVERED="delivered"),
                            FindingStatusChoices=SimpleNamespace(RESOLVED="resolved"), timezone=timezone, timedelta=timedelta)
        rule = SimpleNamespace(repeat_minutes=0, cooldown_minutes=60)
        finding = SimpleNamespace(status="active", first_detected=timezone.now()-timedelta(days=11))
        self.assertTrue(scope["_recent_event"](rule, None, finding))
        rule.repeat_minutes = 1440
        self.assertFalse(scope["_recent_event"](rule, None, finding))
        finding.status = "resolved"
        self.assertTrue(scope["_recent_event"](rule, None, finding))
        events.filter.assert_any_call(payload_summary__finding_status="resolved")

    def test_settings_validate_destinations_and_preserve_stored_webhook(self):
        line_field = definitions("netbox_certificates/forms_v1.py", ["LineListField"], forms=forms)["LineListField"]
        scope = definitions("netbox_certificates/alert_settings.py", ["AlertSettingsForm"], forms=forms,
                            LineListField=line_field, FindingSeverityChoices=[("critical", "Critical")], transaction=transaction, validate_email=validate_email)
        form_type = scope["AlertSettingsForm"]
        base = dict(categories=["validity"], expiration_days=30, cooldown_minutes=60, repeat_minutes=0,
                    smtp_security="starttls", subject_prefix="Test")
        self.assertTrue(form_type(base).is_valid())
        self.assertFalse(form_type({**base, "enabled": "on"}).is_valid())
        invalid = form_type({**base, "email_enabled": "on", "recipients": "not-an-email"})
        self.assertFalse(invalid.is_valid())
        self.assertIn("recipients", invalid.errors)
        configured = SimpleNamespace(rule=None, email_channel=None, webhook_channel=SimpleNamespace(
            enabled=True, webhook_verify_tls=True, webhook_url_encrypted="ciphertext"))
        self.assertTrue(form_type({**base, "enabled": "on", "webhook_enabled": "on"}, config=configured).is_valid())
        invalid = form_type({**base, "webhook_headers": '{"Authorization": 123}'})
        self.assertFalse(invalid.is_valid())

    def test_url_lines_round_trip_without_json(self):
        field = definitions("netbox_certificates/forms_v1.py", ["LineListField"], forms=forms)["LineListField"](required=False)
        self.assertEqual(field.clean("https://one.test\n\n https://two.test "), ["https://one.test", "https://two.test"])
        self.assertEqual(field.prepare_value(["a", "b"]), "a\nb")


class RoutesAndMigrations(unittest.TestCase):
    def test_every_configured_row_action_has_a_route(self):
        routes = (ROOT / "netbox_certificates/urls.py").read_text()
        tree = ast.parse((ROOT / "netbox_certificates/tables_v1.py").read_text())
        for table in (n for n in tree.body if isinstance(n, ast.ClassDef)):
            action = next(n for n in table.body if isinstance(n, ast.Assign) and any(getattr(t, "id", "") == "actions" for t in n.targets))
            names = ast.literal_eval(next(k.value for k in action.value.keywords if k.arg == "actions"))
            for name in names:
                self.assertIn(f'name="{table.name.removesuffix("Table").lower()}_{name}"', routes)

    def test_migration_retains_verification_defaults(self):
        spec = importlib.util.spec_from_file_location("alert_migration", ROOT / "netbox_certificates/migrations/0019_alert_settings.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for operation in module.Migration.operations[:2]:
            self.assertTrue(operation.field.default)
        singleton = module.Migration.operations[2]
        self.assertEqual(singleton.name, "AlertSettings")
        self.assertEqual(singleton.options["default_permissions"], ())


class TemplateBehavior(unittest.TestCase):
    def test_redesigned_pages_render_with_django(self):
        import django
        from django.template import Context, Engine, Library
        from django.test import override_settings
        from django.urls import include, path
        from types import ModuleType
        django.setup()
        url_module = ModuleType("revision_template_urls")
        source = ast.parse((ROOT / "netbox_certificates/urls.py").read_text())
        patterns = []
        for node in ast.walk(source):
            if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "path":
                name = next((kw.value.value for kw in node.keywords if kw.arg == "name"), None)
                if name:
                    patterns.append(path(node.args[0].value, lambda request: None, name=name))
        url_module.urlpatterns = [path("plugins/", include(([path("ssl/", include((patterns, "netbox_certificates")))], "plugins")))]
        shell = "{% block title %}{% endblock %}{% block content %}{% endblock %}{% block form %}{% endblock %}"
        engine = Engine(loaders=[("django.template.loaders.locmem.Loader", {
            "generic/_base.html": shell, "generic/object_edit.html": shell,
        }), ("django.template.loaders.filesystem.Loader", [str(ROOT / "netbox_certificates/templates")])],
                        libraries={"static": "django.templatetags.static"})
        library = Library()
        library.simple_tag(lambda field: str(field), name="render_field")
        library.simple_tag(lambda form: "", name="render_custom_fields")
        engine.template_libraries["form_helpers"] = library
        form_type = definitions("netbox_certificates/forms.py", ["BundleExportForm"], forms=forms)["BundleExportForm"]
        node = dict(id=1, name="Parent <unsafe>", url="/groups/1/", service_count=0, artifact_count=0,
                    children=[dict(id=2, name="Child", url="/groups/2/", children=[])])
        with override_settings(ROOT_URLCONF=url_module, STATIC_URL="/static/"):
            for name in ("bundle_export", "healthfinding_list", "artifactgroup_tree_list", "alert_settings", "service_edit"):
                template = engine.get_template(f"netbox_certificates/{name}.html")
                html = template.render(Context({"form": form_type(), "group_tree": [node]}))
                self.assertTrue(html.strip())
                if name == "artifactgroup_tree_list":
                    self.assertIn("Parent &lt;unsafe&gt;", html)
                    self.assertIn("Child", html)
                    self.assertNotIn('id="filters-form"', html)


if __name__ == "__main__":
    unittest.main()
