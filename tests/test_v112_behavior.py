"""Focused v1.1.2 regressions; no live NetBox instance required."""
import ast
import hashlib
import importlib.util
import io
import json
import re
import sys
import tarfile
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from django import forms
from django.http import FileResponse, HttpResponse, QueryDict
from django.utils.html import format_html, format_html_join
from django.utils.http import content_disposition_header
from django.views import View

from test_revision_behavior import ROOT, definitions


spec = importlib.util.spec_from_file_location("export_names", ROOT / "netbox_certificates/export_names.py")
names = importlib.util.module_from_spec(spec)
spec.loader.exec_module(names)


class GroupFormRegression(unittest.TestCase):
    def test_add_and_edit_initialize_services_without_injected_global(self):
        # Execute the production constructor, including its imports. Injecting a
        # global Service here would conceal the actual v1.1.1 NameError.
        source = ast.parse((ROOT / "netbox_certificates/forms.py").read_text(encoding="utf-8"))
        cls = next(node for node in source.body if isinstance(node, ast.ClassDef) and node.name == "ArtifactGroupForm")
        cls.body = [node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name in {"__init__", "_selected_ids"}]
        cls.bases = [ast.Name(id="BaseForm", ctx=ast.Load())]

        class BaseForm(forms.Form):
            parent = forms.ChoiceField(required=False)
            members = forms.MultipleChoiceField(required=False)

            def __init__(self, *args, instance, **kwargs):
                self.instance = instance
                super().__init__(*args, **kwargs)

        def inventory(pk, name):
            queryset = MagicMock()
            queryset.__iter__.side_effect = lambda: iter([SimpleNamespace(pk=pk, name=name)])
            queryset.all.return_value = queryset
            queryset.order_by.return_value = queryset
            queryset.exclude.return_value = queryset
            queryset.filter.return_value = queryset
            queryset.values_list.return_value = [pk]
            manager = Mock(all=Mock(return_value=queryset), restrict=Mock(return_value=queryset))
            return SimpleNamespace(objects=manager), queryset

        scope = {"__name__": "isolated.forms", "__package__": "isolated", "BaseForm": BaseForm, "DynamicModelMultipleChoiceField": lambda queryset, **kwargs: forms.MultipleChoiceField(**kwargs)}
        for label in ("ArtifactGroup", "Certificate", "PrivateKey", "CSR", "Bundle"):
            scope[label], _ = inventory(1, label)
        service, service_qs = inventory(42, "Web service")
        module = ModuleType("isolated.models_v1")
        module.Service = service
        exec(compile(ast.fix_missing_locations(ast.Module(body=[cls], type_ignores=[])), "forms.py", "exec"), scope)
        for pk in (None, 2):
            instance = SimpleNamespace(pk=pk, descendant_ids=lambda: [3], ancestor_ids=lambda: [1])
            user = object()
            with patch.dict(sys.modules, {"isolated.models_v1": module}):
                form = scope["ArtifactGroupForm"](instance=instance, user=user)
            choices = dict(form.fields["members"].choices)
            self.assertEqual(choices["Services"], [("service:42", "Web service")])
            self.assertIn("CSRs", choices)
            self.assertIs(form._member_querysets["service"], service_qs)
            service.objects.restrict.assert_called_with(user, "change")
            if pk:
                self.assertIn("service:42", form.fields["members"].initial)
                self.assertEqual(form.fields["member_service"].initial, [42])
                scope["ArtifactGroup"].objects.restrict.return_value.exclude.assert_any_call(pk__in={2, 3})


class BundleNamesRegression(unittest.TestCase):
    def bundle(self, name="example.com"):
        return SimpleNamespace(pk=7, name="Internal bundle label", certificate=SimpleNamespace(
            pk=1, name=name, material="CERT"), private_key=SimpleNamespace(pk=2, encrypted_material="cipher"),
            private_key_id=2, csr=None, chain_certificates=SimpleNamespace(all=lambda: []))

    def test_names_and_collision_handling(self):
        bundle = self.bundle()
        self.assertEqual(names.bundle_export_name(bundle, ".zip"), "example.com's Bundle.zip")
        self.assertEqual(names.pfx_export_name(bundle), "example.com.pfx")
        used = set()
        self.assertEqual(names.unique_bundle_directory(bundle, used), "example.com's Bundle")
        self.assertEqual(names.unique_bundle_directory(self.bundle("EXAMPLE.COM"), used), "EXAMPLE.COM's Bundle (2)")
        bundle.certificate = None
        self.assertEqual(names.bundle_export_name(bundle), "Internal bundle label's Bundle")

    def test_unsafe_and_unicode_names(self):
        for name in ('../../bad\\name\r\n".com', '...', '*', 'CON', 'LPT1.com', 'x' * 300, 'Ù…Ø«Ø§Ù„' * 90):
            result = names.certificate_export_name(self.bundle(name))
            self.assertNotRegex(result, r'[<>:"/\\|?*\x00-\x1f]')
            self.assertNotIn(result, ('', '.', '..', 'CON', 'LPT1.com'))
            self.assertLessEqual(len(result), 121)
            self.assertLessEqual(len(result.encode("utf-8")), 161)
        result = names.bundle_export_name(self.bundle("Ù…Ø«Ø§Ù„.com"), ".zip")
        self.assertIn("filename*=utf-8''", content_disposition_header(True, result))

    def export_scope(self):
        return definitions("netbox_certificates/bulk_export.py", [
            "_bundle_members", "_bundle_chain", "_write_member", "_secure_file_response", "SingleBundleArchiveExportView",
        ], bundle_export_name=names.bundle_export_name, pfx_export_name=names.pfx_export_name,
            _artifact_filename=lambda obj, ext: f"artifact-{obj.pk}{ext}", ordered_chain=lambda obj: [],
            build_pfx=Mock(return_value=b"PFX"), decrypt_private_key=Mock(return_value=b"KEY"),
            LoginRequiredMixin=type("LoginRequiredMixin", (), {}), View=View,
            _object_manifest=lambda obj: {"id": obj.pk}, datetime=datetime, timezone=timezone,
            hashlib=hashlib, json=json, zipfile=zipfile, tempfile=tempfile, FileResponse=FileResponse)

    def test_single_ui_zip_tar_names_and_manifest(self):
        scope = self.export_scope()
        view = scope["SingleBundleArchiveExportView"]()
        view.bundle_options = {"export_pfx": True, "include_chain": False, "protect_pfx": False}
        for fmt in ("zip", "tar"):
            response = getattr(view, "_" + fmt)(self.bundle())
            self.assertEqual(response["Content-Disposition"], f'attachment; filename="example.com\'s Bundle.{fmt}"')
            data = b"".join(response.streaming_content)
            response.close()
            if fmt == "zip":
                with zipfile.ZipFile(io.BytesIO(data)) as archive:
                    files = {name: archive.read(name) for name in archive.namelist()}
            else:
                with tarfile.open(fileobj=io.BytesIO(data)) as archive:
                    files = {member.name: archive.extractfile(member).read() for member in archive.getmembers()}
            path = "example.com's Bundle/example.com.pfx"
            self.assertEqual(files[path], b"PFX")
            manifest = json.loads(files["manifest.json"])
            self.assertEqual(manifest["files"][0]["path"], path)
            self.assertEqual(manifest["files"][0]["sha256"], hashlib.sha256(b"PFX").hexdigest())
            self.assertEqual(set(files), {path, "manifest.json"})

    def test_bulk_archive_keeps_both_bundles_when_certificate_names_match(self):
        first, second = self.bundle(), self.bundle()
        second.pk = 8
        queryset = MagicMock()
        queryset.select_related.return_value = queryset
        queryset.prefetch_related.return_value = queryset
        queryset.filter.return_value = queryset
        queryset.iterator.return_value = iter([first, second])
        scope = self.export_scope()
        scope.update(EXPORT_CONFIG={"bundle": {"model": object, "action": "export", "filterset": object, "filename": "bundles-material.zip"}},
                     Bundle=object, require_action_permission=Mock(), action_queryset=lambda *args: queryset,
                     apply_current_filters=lambda *args, **kwargs: (queryset, None, QueryDict()),
                     unique_bundle_directory=names.unique_bundle_directory)
        view = definitions("netbox_certificates/bulk_export.py", ["BulkMaterialExportView"], **scope)["BulkMaterialExportView"]()
        view.bundle_options = {"export_pfx": True, "include_chain": False, "protect_pfx": False}
        response = view._export(SimpleNamespace(user=SimpleNamespace(is_superuser=True)), "bundle")
        data = b"".join(response.streaming_content)
        response.close()
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            self.assertEqual(set(archive.namelist()), {
                "example.com's Bundle/example.com.pfx", "example.com's Bundle (2)/example.com.pfx", "manifest.json",
            })
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest["count"], 2)
            self.assertEqual({item["id"] for item in manifest["objects"]}, {7, 8})

    def test_api_zip_tar_names_and_pfx(self):
        queryset = MagicMock()
        queryset.select_related.return_value = queryset
        queryset.prefetch_related.return_value = queryset
        queryset.get.return_value = self.bundle()
        scope = definitions("netbox_certificates/api/views.py", [
            "_bundle_filename", "_secure_response", "_archive", "BundleViewSet",
        ], bundle_export_name=names.bundle_export_name, pfx_export_name=names.pfx_export_name,
            Bundle=SimpleNamespace(objects=queryset), BundleSerializer=object, BundleFilterSet=object,
            NetBoxModelViewSet=object, action=lambda **kwargs: lambda func: func, IsAuthenticated=object,
            _require_sensitive_token=Mock(), _require_superuser_token=Mock(), _bool_value=lambda value, default: default if value is None else bool(value),
            action_queryset=lambda *args: queryset, build_pfx=Mock(return_value=b"PFX"),
            HttpResponse=HttpResponse, content_disposition_header=content_disposition_header,
            io=io, zipfile=zipfile, tarfile=tarfile)
        for fmt in ("zip", "tar"):
            response = scope["BundleViewSet"]().export(SimpleNamespace(
                data={"pfx": True, "format": fmt, "allow_unencrypted_pfx": True}, user=object()), pk=7)
            self.assertIn(f"example.com's Bundle.{fmt}", response["Content-Disposition"])
            archive = zipfile.ZipFile(io.BytesIO(response.content)) if fmt == "zip" else tarfile.open(fileobj=io.BytesIO(response.content))
            with archive:
                self.assertEqual(archive.namelist() if fmt == "zip" else archive.getnames(), ["example.com.pfx"])
            scope["_require_superuser_token"].assert_called()


class FindingDisplayRegression(unittest.TestCase):
    def scope(self):
        labels = definitions("netbox_certificates/labels.py", ["display_label"],
                             _ACRONYMS=re.compile(r"\b(csrs?|url|id)\b", re.I))
        return definitions("netbox_certificates/finding_display.py", ["finding_object_link", "finding_data_display"],
                           object_allowed=lambda user, obj: obj.visible, display_label=labels["display_label"],
                           format_html=format_html, format_html_join=format_html_join, json=json)

    def test_object_links_escape_names_and_hide_inaccessible_objects(self):
        class Object:
            visible = True
            def __str__(self): return 'example <script>alert(1)</script>'
            def get_absolute_url(self): return "/certificates/7/"
        obj = Object()
        render = self.scope()["finding_object_link"]
        self.assertIn('href="/certificates/7/"', render(obj, object()))
        self.assertIn("&lt;script&gt;", render(obj, object()))
        obj.visible = False
        self.assertIsNone(render(obj, object()))
        self.assertIsNone(render(None, object()))

    def test_evidence_is_labeled_escaped_and_keeps_zero(self):
        render = self.scope()["finding_data_display"]
        output = render({"days_remaining": 0, "uncovered_names": ["<script>"], "policy": {"name": "A&B"}})
        self.assertIn("Days remaining:</strong> 0", output)
        self.assertIn("Uncovered names:", output)
        self.assertIn("&lt;script&gt;", output)
        self.assertNotIn("<script>", output)
        self.assertIsNone(render({}))

    def test_detail_context_uses_links_and_readable_evidence(self):
        helpers = self.scope()
        view_base = type("ObjectView", (), {"actions": ()})
        scope = definitions("netbox_certificates/views_v1.py", ["V1ObjectView", "HealthFindingView"],
                            generic=SimpleNamespace(ObjectView=view_base), HealthFinding=SimpleNamespace(objects=Mock()),
                            display_label=lambda label: label, object_allowed=helpers["object_allowed"],
                            finding_object_link=helpers["finding_object_link"], finding_data_display=helpers["finding_data_display"])
        affected = MagicMock(visible=True, get_absolute_url=Mock(return_value="/certificates/1/"))
        affected.__str__.return_value = "example.com"
        related = MagicMock(visible=False)
        finding = SimpleNamespace(affected_object=affected, related_object=related,
                                  details={"reason": "expired"}, evidence={"days_remaining": -1})
        rows = dict(scope["HealthFindingView"]().get_extra_context(SimpleNamespace(user=object()), finding)["detail_rows"])
        self.assertIn('href="/certificates/1/"', rows["Affected Object"])
        self.assertIsNone(rows["Related Object"])
        self.assertIn("Days remaining:</strong> -1", rows["Evidence"])

    def test_populated_table_renders_links_evidence_and_escapes_summary(self):
        from django.template import Context, Engine, Library
        from django.urls import include, path
        from django.test import override_settings
        helpers = self.scope()
        routes = ModuleType("finding_template_urls")
        routes.urlpatterns = [path("plugins/", include(([path("ssl/", include(([
            path("certificates/", lambda request: None, name="certificate_list"),
            path("health/", lambda request: None, name="health"),
        ], "netbox_certificates")))], "plugins")))]
        engine = Engine(loaders=[("django.template.loaders.locmem.Loader", {
            "generic/_base.html": "{% block content %}{% endblock %}",
        }), ("django.template.loaders.filesystem.Loader", [str(ROOT / "netbox_certificates/templates")])])
        tags = Library()
        tags.simple_tag(lambda field: "", name="render_field")
        engine.template_libraries["form_helpers"] = tags
        static_tags = Library()
        static_tags.simple_tag(lambda path: "/static/" + path, name="static")
        engine.template_libraries["static"] = static_tags
        finding = SimpleNamespace(pk=7, severity="critical", summary="Expired <script>",
            get_severity_display=lambda: "Critical", get_status_display=lambda: "Active", category="validity", code="EXPIRED",
            get_absolute_url=lambda: "/health/7/", affected_link=format_html('<a href="{}">{}</a>', "/certificates/1/", "example.com"),
            related_link=None, details_display=None, evidence_display=helpers["finding_data_display"]({"days_remaining": -1}))
        with override_settings(ROOT_URLCONF=routes):
            html = engine.get_template("netbox_certificates/healthfinding_list.html").render(Context({"findings": [finding]}))
        self.assertIn('href="/certificates/1/"', html)
        self.assertIn("Days remaining:</strong> -1", html)
        self.assertIn("Expired &lt;script&gt;", html)
        self.assertIn("Affected object", html)

    def test_plural_normalization(self):
        labels = definitions("netbox_certificates/labels.py", ["display_label"], _ACRONYMS=re.compile(r"\bcsrs?\b", re.I))
        for value in ("Csrs", "CSRS", "csrs", "CSRs"):
            self.assertEqual(labels["display_label"](value), "CSRs")
        self.assertEqual(labels["display_label"]("Csr"), "CSR")

    def test_alert_explanation_removed_and_sample_actions_preserved(self):
        template = (ROOT / "netbox_certificates/templates/netbox_certificates/alert_settings.html").read_text(encoding="utf-8")
        self.assertNotIn("Expiration alerts use each certificate", template)
        self.assertIn('value="test_email"', template)
        self.assertIn('value="test_webhook"', template)
