"""Delivery, version, and selection regressions without a live NetBox server."""
import ast
import json
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.core.mail import EmailMultiAlternatives
from django.core.mail.backends.locmem import EmailBackend
from django import forms
from django.template import Context, Engine
from django.utils import timezone

from test_revision_behavior import ROOT, definitions


class NotificationTests(unittest.TestCase):
    def renderer(self):
        engine = Engine(dirs=[str(ROOT / "netbox_certificates/templates")])
        return definitions("netbox_certificates/services/email_templates.py", ["render_notification"],
            json=json, timezone=timezone,
            render_to_string=lambda name, context: engine.get_template(name).render(Context(context, use_l10n=False)),
        )["render_notification"]

    def test_html_escapes_untrusted_content_and_shows_current_version(self):
        text, html = self.renderer()("Alert", {
            "rule": "Daily checks", "object": {"display": "<script>bad</script>"},
            "finding": {"summary": "Expired <img src=x>", "severity": "high", "status": "active",
                        "code": "CERT_EXPIRED", "details": "Certificate expired", "evidence": {"days": -1}},
        })
        self.assertIn("Expired &lt;img src=x&gt;", html)
        self.assertNotIn("<script>", html)
        self.assertIn("Daily checks", html)
        self.assertIn("days", html)
        self.assertIn("Expired <img src=x>", text)
        version = definitions("netbox_certificates/services/email_templates.py", ["render_notification"])["__version__"]
        self.assertIn(f"NetBox Certificates {version}", html)

    def test_test_recovery_and_expiration_use_the_same_design(self):
        for payload, expected in (
            ({"type": "netbox-certificates-alert-test", "channel": "SMTP"}, "Email delivery test"),
            ({"finding": {"status": "resolved", "summary": "Renewed"}}, "Certificate recovery"),
            ({"reports": [{"title": "example.com", "badge": "Expired", "rows": [("Serial", "123")]}]}, "example.com"),
        ):
            with self.subTest(payload=payload):
                text, html = self.renderer()("Alert", payload)
                self.assertIn(expected, html)
                self.assertIn(expected, text)
                self.assertIn("max-width:640px", html)

    def test_email_is_multipart_with_html_and_readable_fallback(self):
        import django.core.mail as mail
        connection = EmailBackend()
        send = definitions("netbox_certificates/services/alerts_v1.py", ["_send_email"],
            render_notification=self.renderer(), _email_connection=lambda channel: connection,
            EmailMultiAlternatives=EmailMultiAlternatives, settings=SimpleNamespace(DEFAULT_FROM_EMAIL="netbox@example.test"),
        )["_send_email"]
        channel = SimpleNamespace(from_email="netbox@example.test", recipients=["operator@example.test"])
        self.assertEqual(send(channel, "Test", {"type": "netbox-certificates-alert-test"}), 1)
        message = mail.outbox[-1]
        self.assertEqual(message.message().get_content_type(), "multipart/alternative")
        self.assertEqual(message.alternatives[0].mimetype, "text/html")
        self.assertIn("SMTP configuration", message.body)
        self.assertIn("NETBOX CERTIFICATES", message.alternatives[0].content)

    def webhook(self):
        secrets = types.ModuleType("isolated.secret_v1")
        secrets.decrypt_text = lambda value: "https://example.test/hook"
        secrets.decrypt_json = lambda value: {"X-Test": "retained"}
        request = Mock(return_value=SimpleNamespace(status_code=204, raise_for_status=Mock()))
        send = definitions("netbox_certificates/services/alerts_v1.py", ["_send_webhook"],
                           __package__="isolated", json=json, requests=SimpleNamespace(request=request))["_send_webhook"]
        channel = SimpleNamespace(webhook_method="POST", webhook_url_encrypted="cipher", webhook_headers_encrypted="cipher", webhook_verify_tls=False)
        return send, request, secrets, channel

    def test_all_webhook_methods_keep_tls_headers_and_payload(self):
        send, request, secrets, channel = self.webhook()
        payload = {"finding": {"summary": "Expires soon", "id": 3}}
        with patch.dict(sys.modules, {secrets.__name__: secrets}):
            for method in ("POST", "GET", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"):
                with self.subTest(method=method):
                    channel.webhook_method = method
                    send(channel, payload)
                    self.assertEqual(request.call_args.args[0], method)
                    options = request.call_args.kwargs
                    self.assertFalse(options["verify"])
                    self.assertFalse(options["allow_redirects"])
                    self.assertEqual(options["headers"]["X-Test"], "retained")
                    if method in {"GET", "HEAD", "OPTIONS"}:
                        self.assertEqual(json.loads(options["params"]["payload"]), payload)
                        self.assertNotIn("json", options)
                    else:
                        self.assertEqual(options["json"], payload)
                        self.assertNotIn("params", options)

    def test_webhook_rejects_unknown_methods_and_redirects(self):
        send, request, secrets, channel = self.webhook()
        with patch.dict(sys.modules, {secrets.__name__: secrets}):
            channel.webhook_method = "TRACE"
            with self.assertRaises(ValueError):
                send(channel, {})
            request.assert_not_called()
            channel.webhook_method = "POST"
            request.return_value.status_code = 302
            with self.assertRaisesRegex(ValueError, "redirects"):
                send(channel, {})


class SharedVersionTests(unittest.TestCase):
    def test_native_group_selections_and_clearing_feed_existing_membership_logic(self):
        tree = ast.parse((ROOT / "netbox_certificates/forms.py").read_text(encoding="utf-8"))
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ArtifactGroupForm")
        cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name in {"clean", "_selected_ids"}]
        cls.bases = [ast.Name(id="Base", ctx=ast.Load())]
        scope = {"Base": forms.Form}
        exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), "native_members", "exec"), scope)
        form = scope["ArtifactGroupForm"]({})
        form.instance = SimpleNamespace(pk=None)
        form._member_querysets = {kind: None for kind in ("group", "certificate", "privatekey", "csr", "bundle", "service")}
        form.cleaned_data = {f"member_{kind}": [SimpleNamespace(pk=index)] for index, kind in enumerate(form._member_querysets, 1)}
        self.assertEqual(form.clean()["members"], [f"{kind}:{index}" for index, kind in enumerate(form._member_querysets, 1)])
        form.cleaned_data = {f"member_{kind}": [] for kind in form._member_querysets}
        self.assertEqual(form.clean()["members"], [])

    def test_all_manifest_and_alert_versions_use_the_runtime_constant(self):
        for relative in ("bulk_export.py", "export_v1.py", "inventory_export.py", "services/alerts_v1.py", "services/alerts.py"):
            tree = ast.parse((ROOT / "netbox_certificates" / relative).read_text(encoding="utf-8"))
            values = [value for node in ast.walk(tree) if isinstance(node, ast.Dict)
                      for key, value in zip(node.keys, node.values)
                      if isinstance(key, ast.Constant) and key.value == "plugin_version"]
            self.assertTrue(values, relative)
            self.assertTrue(all(isinstance(value, ast.Name) and value.id == "__version__" for value in values), relative)

    def test_custom_bulk_pages_have_controls_and_health_keeps_filters(self):
        templates = ROOT / "netbox_certificates/templates/netbox_certificates"
        for name in ("artifactgroup_tree_list.html", "healthfinding_list.html", "inventory_export.html"):
            html = (templates / name).read_text(encoding="utf-8")
            self.assertIn("bulk_selection.html", html)
            self.assertIn("bulk_selection.js", html)
            self.assertIn("data-bulk-select", html)
        health = (templates / "healthfinding_list.html").read_text(encoding="utf-8")
        self.assertIn('name="_all"', health)
        for action in ("edit", "delete"):
            self.assertIn(f"healthfinding_bulk_{action}' %}}?{{{{ filter_query }}}}", health)
