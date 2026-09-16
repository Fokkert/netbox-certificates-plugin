"""Serializer discovery, event context, schedules, editors, and derived fields."""
import ast
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from itertools import groupby
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django import forms
from django.template import Context, Engine
from django.utils.module_loading import import_string
from rest_framework import serializers

from test_revision_behavior import ROOT, definitions


class SerializerDiscovery(unittest.TestCase):
    def test_netbox_canonical_lookup_finds_every_public_model_serializer(self):
        # NetBox 4.5.9 uses import_string(app.api.serializers.ModelSerializer).
        # Execute the real facade with implementation modules isolated from NetBox.
        package = types.ModuleType("discovery_test")
        package.__path__ = []
        api = types.ModuleType("discovery_test.api")
        api.__path__ = []
        modules = {"discovery_test": package, "discovery_test.api": api}
        for name in ("base_serializers", "v1_serializers"):
            module = types.ModuleType(f"discovery_test.api.{name}")
            tree = ast.parse((ROOT / f"netbox_certificates/api/{name}.py").read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, ast.ClassDef):
                    setattr(module, node.name, type(node.name, (), {}))
            modules[module.__name__] = module
        facade = types.ModuleType("discovery_test.api.serializers")
        facade.__package__ = "discovery_test.api"
        modules[facade.__name__] = facade
        with patch.dict(sys.modules, modules):
            exec((ROOT / "netbox_certificates/api/serializers.py").read_text(encoding="utf-8"), facade.__dict__)
            for name in ("Certificate", "CSR", "PrivateKey", "Bundle", "ArtifactGroup", "Service",
                         "ObjectLink", "HealthFinding", "AlertRule", "AlertChannel", "AlertEvent"):
                with self.subTest(model=name):
                    resolved = import_string(f"discovery_test.api.serializers.{name}Serializer")
                    self.assertEqual(resolved.__name__, name + "Serializer")

    def test_event_display_fields_accept_request_none_and_missing_context(self):
        tree = ast.parse((ROOT / "netbox_certificates/api/v1_serializers.py").read_text(encoding="utf-8"))
        names = {"get_source_display", "get_target_display", "get_affected_display", "get_related_display"}
        scope = {"object_allowed": lambda user, obj: user is not None and obj is not None}
        methods = [node for cls in tree.body if isinstance(cls, ast.ClassDef)
                   for node in cls.body if isinstance(node, ast.FunctionDef) and node.name in names]
        exec(compile(ast.Module(body=methods, type_ignores=[]), "display_methods", "exec"), scope)
        obj = SimpleNamespace(source="certificate", target="key", affected_object="certificate", related_object="key")
        for context in ({}, {"request": None}):
            for name in names:
                with self.subTest(context=context, method=name):
                    self.assertIsNone(scope[name](SimpleNamespace(context=context), obj))
        self.assertEqual(scope["get_source_display"](SimpleNamespace(context={"request": SimpleNamespace(user=object())}), obj), "certificate")


class DerivedInformation(unittest.TestCase):
    def test_legacy_adapter_keeps_real_relationship_origin_and_enabled_state(self):
        names = ("source_type", "source_id", "target_type", "target_id", "relation", "origin", "active", "note")
        model = SimpleNamespace(_meta=SimpleNamespace(get_fields=lambda: [SimpleNamespace(name=name) for name in names]))
        adapt = definitions("netbox_certificates/signals_v1.py", ["_field_name", "_legacy_link_values"],
                            LegacyArtifactLink=model, _legacy_content_type=lambda obj, name: getattr(obj, name))["_legacy_link_values"]
        link = SimpleNamespace(source_type=1, source_id=2, target_type=3, target_id=4,
                               relation="issuer", origin="automatic", active=False, note="Verified issuer")
        for origin in ("automatic", "bundle", "pfx"):
            link.origin = origin
            result = adapt(link)
            self.assertEqual(result["relationship"], "issuer")
            self.assertEqual(result["label"], "Verified issuer")
            self.assertTrue(result["automatic"])
            self.assertFalse(result["enabled"])
        link.origin, link.active = "manual", True
        self.assertFalse(adapt(link)["enabled"])
        link.relation = "related"
        self.assertFalse(adapt(link)["automatic"])
        self.assertTrue(adapt(link)["enabled"])

    def test_link_migration_repairs_only_identifiable_legacy_mirrors(self):
        legacy, public = Mock(), Mock()
        old = SimpleNamespace(source_type_id=1, source_id=2, target_type_id=3, target_id=4,
                              relation="key_match", origin="automatic", active=True, note="")
        legacy.objects.using.return_value.all.return_value.iterator.return_value = iter([old])
        legacy.objects.using.return_value.filter.return_value.exists.return_value = False
        apps = SimpleNamespace(get_model=lambda app, name: legacy if name == "ArtifactLink" else public)
        repair = definitions("netbox_certificates/migrations/0023_preferences_and_derived_fields.py", ["repair_mirrored_links"])["repair_mirrored_links"]
        repair(apps, SimpleNamespace(connection=SimpleNamespace(alias="default")))
        write = public.objects.using.return_value.update_or_create.call_args.kwargs
        self.assertEqual(write["relationship"], "key_match")
        self.assertTrue(write["defaults"]["automatic"])
        cleanup = public.objects.using.return_value.filter.call_args.kwargs
        self.assertEqual(cleanup["relationship"], "related")
        self.assertEqual(cleanup["description"], "Manual pre-1.0 artifact relationship mirrored into ObjectLink.")

    def test_api_rejects_derived_values_but_accepts_names(self):
        bundle_model = object()
        mixin = definitions("netbox_certificates/api/base_serializers.py", ["DerivedCryptoFieldsMixin"],
                            Bundle=bundle_model, serializers=serializers)["DerivedCryptoFieldsMixin"]

        class Base:
            def to_internal_value(self, data):
                return data

        class CertificateInput(mixin, Base):
            class Meta:
                model = object()
                read_only_fields = ("supersedes", "parent_certificate", "subject", "issuer", "fingerprint_sha256", "is_ca", "status")

        instance = CertificateInput()
        self.assertEqual(instance.to_internal_value({"name": "Friendly name"}), {"name": "Friendly name"})
        for name in instance.Meta.read_only_fields:
            with self.subTest(field=name), self.assertRaises(serializers.ValidationError):
                instance.to_internal_value({name: "override"})

    def test_supersedes_is_recomputed_and_import_order_independent(self):
        def certificate(pk, days, supersedes=None):
            return SimpleNamespace(pk=pk, is_ca=False, subject="CN=example.test", subject_alternative_names=["example.test"],
                                   valid_to=datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=days),
                                   supersedes_id=supersedes, supersedes=None, save=Mock())
        old, middle, renewed = certificate(1, 1), certificate(2, 20), certificate(3, 40, 99)
        peer = certificate(4, 40)
        queryset = Mock()
        queryset.iterator.return_value = iter([renewed, old, peer, middle])
        model = SimpleNamespace(objects=Mock(all=Mock(return_value=queryset)))
        scope = definitions("netbox_certificates/services/renewal.py", ["renewal_identity", "reconcile_supersedes"],
                            Certificate=model, defaultdict=defaultdict, groupby=groupby)
        scope["reconcile_supersedes"]()
        self.assertIsNone(old.supersedes)
        self.assertIs(middle.supersedes, old)
        self.assertIs(renewed.supersedes, middle)
        self.assertIs(peer.supersedes, middle)
        renewed.save.assert_called_once_with(update_fields=("supersedes",))

    def test_material_replacement_checks_cover_all_three_artifact_types(self):
        source = (ROOT / "netbox_certificates/api/base_serializers.py").read_text(encoding="utf-8")
        for name in ("CertificateSerializer", "CSRSerializer", "PrivateKeySerializer"):
            cls = next(node for node in ast.parse(source).body if isinstance(node, ast.ClassDef) and node.name == name)
            validate = next(node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "validate")
            body = ast.get_source_segment(source, validate)
            self.assertIn("Stored material is immutable", body)
            self.assertIn("self.instance is not None", body)


class BackgroundPreferences(unittest.TestCase):
    def test_preference_fields_reject_invalid_intervals_and_key_sizes(self):
        tree = ast.parse((ROOT / "netbox_certificates/preferences.py").read_text(encoding="utf-8"))
        cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "PreferencesForm")
        # Exercise the declared Django fields independently of the NetBox model.
        assignments = [node for node in cls.body if isinstance(node, ast.Assign)]
        scope = {"forms": forms, "INTERVALS": [(n, str(n)) for n in (5, 15, 30, 60, 180, 360, 720, 1440)]}
        exec(compile(ast.Module(body=assignments, type_ignores=[]), "preference_fields", "exec"), scope)
        form_type = type("PreferenceFields", (forms.Form,), {key: value for key, value in scope.items() if isinstance(value, forms.Field)})
        values = {"health_scan_interval_minutes": 15, "alert_interval_minutes": 30, "expiration_warning_days": 90, "csr_rsa_bits": 3072}
        self.assertTrue(form_type(values).is_valid())
        for name, invalid in (("health_scan_interval_minutes", 0), ("alert_interval_minutes", 7),
                              ("expiration_warning_days", 29), ("expiration_warning_days", 3651), ("csr_rsa_bits", 1024)):
            with self.subTest(field=name, value=invalid):
                form = form_type({**values, name: invalid})
                self.assertFalse(form.is_valid())
                self.assertIn(name, form.errors)

    def test_processing_schedule_boundaries(self):
        due = definitions("netbox_certificates/jobs_v1.py", ["processing_due"], timedelta=timedelta)["processing_due"]
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.assertTrue(due(None, 15, now))
        self.assertFalse(due(now - timedelta(minutes=14, seconds=59), 15, now))
        self.assertTrue(due(now - timedelta(minutes=15), 15, now))
        self.assertFalse(due(now + timedelta(minutes=1), 15, now))

    def runner(self, config, health=None):
        manager = Mock()
        manager.get_or_create.return_value = (config, False)
        scan, delivery = health or Mock(return_value={"active": 2}), Mock(return_value={"delivered": 1})
        now = datetime(2026, 1, 1, tzinfo=timezone.utc)
        scope = definitions("netbox_certificates/jobs_v1.py", ["processing_due", "CertificateHealthAndAlertJob"],
                            timedelta=timedelta, system_job=lambda **kwargs: lambda cls: cls, JobRunner=object,
                            timezone=SimpleNamespace(now=lambda: now), AlertSettings=SimpleNamespace(objects=manager),
                            call_command=Mock(), refresh_health_findings=scan, dispatch_alerts=delivery)
        runner = scope["CertificateHealthAndAlertJob"]()
        runner.job, runner.logger = SimpleNamespace(interval=15), Mock()
        return runner, manager, scan, delivery

    def test_disabling_scan_keeps_alert_processing_and_due_timestamps(self):
        config = SimpleNamespace(health_scan_enabled=False, last_health_scan=None, last_alert_evaluation=None,
                                 health_scan_interval_minutes=15, alert_interval_minutes=30)
        runner, manager, scan, delivery = self.runner(config)
        runner.run()
        scan.assert_not_called()
        delivery.assert_called_once()
        self.assertEqual(runner.job.interval, 5)
        updated = manager.filter.return_value.update.call_args.kwargs
        self.assertIn("last_alert_evaluation", updated)
        self.assertNotIn("last_health_scan", updated)

    def test_failed_scan_does_not_mark_success_or_send_stale_alerts(self):
        config = SimpleNamespace(health_scan_enabled=True, last_health_scan=None, last_alert_evaluation=None,
                                 health_scan_interval_minutes=15, alert_interval_minutes=15)
        runner, manager, _, delivery = self.runner(config, Mock(side_effect=RuntimeError("scan failed")))
        with self.assertRaises(RuntimeError):
            runner.run()
        manager.filter.return_value.update.assert_not_called()
        delivery.assert_not_called()


class EditorRendering(unittest.TestCase):
    def test_group_membership_sections_keep_selected_values_and_escape_names(self):
        widget = forms.SelectMultiple(choices=[("Certificates", [("certificate:1", "<unsafe>")]),
                                               ("Private Keys", [("privatekey:2", "Key")]), ("Groups", [])])
        context = widget.get_context("members", ["certificate:1", "privatekey:2"], {"id": "id_members"})
        template = Engine().from_string((ROOT / "netbox_certificates/templates/netbox_certificates/widgets/group_members.html").read_text(encoding="utf-8"))
        html = template.render(Context(context))
        self.assertEqual(html.count('name="members"'), 3)
        self.assertEqual(html.count(" selected"), 2)
        self.assertIn("&lt;unsafe&gt;", html)
        self.assertIn('id="id_members_0"', html)
        self.assertIn('id="id_members_1"', html)
        self.assertIn("No editable groups available.", html)

    def test_ca_bookmark_preserves_filters_and_forces_ca_filter(self):
        from django.http import QueryDict
        from django.views import View
        view = definitions("netbox_certificates/retired.py", ["CertificateAuthoritiesRedirectView"],
                           LoginRequiredMixin=type("Login", (), {}), View=View, redirect=lambda value: value)["CertificateAuthoritiesRedirectView"]()
        with patch("django.urls.reverse", return_value="/plugins/ssl-certificates/certificates/"):
            result = view.get(SimpleNamespace(GET=QueryDict("q=Root&is_ca=false")))
        self.assertEqual(result, "/plugins/ssl-certificates/certificates/?q=Root&is_ca=true")
