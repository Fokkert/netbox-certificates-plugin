"""Health filter regressions using real Django validation and SQLite queries."""
import ast
import importlib.util
import unittest
from types import SimpleNamespace
from unittest.mock import Mock

import django
from django import forms
from django.db import connection, models
from django.http import QueryDict
import django_filters

from test_revision_behavior import ROOT, definitions


spec = importlib.util.spec_from_file_location("isolated_filter_fields", ROOT / "netbox_certificates/filter_fields.py")
filter_fields = importlib.util.module_from_spec(spec)
spec.loader.exec_module(filter_fields)


class HealthFilterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        django.setup()

        class FindingRecord(models.Model):
            severity = models.CharField(max_length=20, choices=[("critical", "Critical"), ("warning", "Warning")])
            status = models.CharField(max_length=20, choices=[("active", "Active"), ("resolved", "Resolved")])

            class Meta:
                app_label = "standalone_health_filters"

        cls.model = FindingRecord
        with connection.schema_editor() as editor:
            editor.create_model(cls.model)
        cls.model.objects.bulk_create([
            cls.model(severity="critical", status="active"),
            cls.model(severity="warning", status="active"),
            cls.model(severity="warning", status="resolved"),
        ])
        # Execute the production field declarations, replacing only the NetBox
        # model/base with a small Django model and django-filter's real base.
        source = ast.parse((ROOT / "netbox_certificates/filtersets_v1.py").read_text(encoding="utf-8"))
        health = next(n for n in source.body if isinstance(n, ast.ClassDef) and n.name == "HealthFindingFilterSet")
        nodes = [n for n in health.body if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id in {"severity", "status"} for t in n.targets)]
        scope = {"HealthFinding": cls.model, "OptionalMultipleChoiceFilter": filter_fields.OptionalMultipleChoiceFilter}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "health_filters", "exec"), scope)
        cls.filters = type("HealthFilters", (django_filters.FilterSet,), {
            **{name: scope[name] for name in ("severity", "status")},
            "Meta": type("Meta", (), {"model": cls.model, "fields": ["severity", "status"]}),
        })
        cls.form = definitions("netbox_certificates/forms_v1.py", ["HealthFindingFilterForm"],
            forms=forms, HealthFinding=cls.model,
            FindingSeverityChoices=cls.model._meta.get_field("severity").choices,
            FindingStatusChoices=cls.model._meta.get_field("status").choices,
            OptionalMultipleChoiceField=filter_fields.OptionalMultipleChoiceField,
        )["HealthFindingFilterForm"]

    @classmethod
    def tearDownClass(cls):
        with connection.schema_editor() as editor:
            editor.delete_model(cls.model)

    def test_cleared_optional_choices_return_all_results(self):
        for query in ("", "severity=&status=", "severity=&severity=&status="):
            with self.subTest(query=query):
                data = QueryDict(query)
                filtered = self.filters(data, queryset=self.model.objects.all())
                self.assertTrue(filtered.is_valid(), filtered.errors)
                self.assertEqual(filtered.qs.count(), 3)
                form = self.form(data)
                self.assertTrue(form.is_valid(), form.errors)
                self.assertEqual(form.fields["q"].label, "Search")

    def test_multiple_values_use_or_and_preserve_other_filters(self):
        filtered = self.filters(QueryDict("severity=critical&severity=warning&status=active"), queryset=self.model.objects.all())
        self.assertTrue(filtered.is_valid(), filtered.errors)
        self.assertEqual(filtered.qs.count(), 2)
        filtered = self.filters(QueryDict("severity=&status=resolved"), queryset=self.model.objects.all())
        self.assertTrue(filtered.is_valid(), filtered.errors)
        self.assertEqual(filtered.qs.count(), 1)

    def test_invalid_nonempty_values_remain_errors(self):
        for query in ("severity=unknown", "severity=&severity=unknown", "status=deleted"):
            with self.subTest(query=query):
                data = QueryDict(query)
                self.assertFalse(self.filters(data, queryset=self.model.objects.all()).is_valid())
                self.assertFalse(self.form(data).is_valid())

    def test_choices_render_without_modifier_widgets_or_required_constraints(self):
        form = self.form(QueryDict("severity=critical"))
        self.assertFalse(form.fields["severity"].required)
        self.assertIsInstance(form.fields["severity"].widget, forms.SelectMultiple)
        self.assertIn('value="critical" selected', str(form["severity"]))
        self.assertNotIn("required", str(form["severity"]))


class FindingWorkflowTests(unittest.TestCase):
    def editor(self, status):
        from django.utils import timezone
        instance = SimpleNamespace(status=status, resolved_at=timezone.now(), save=Mock())

        class BaseForm:
            fields = {}

            def save(self, commit=True):
                return instance

        form = definitions("netbox_certificates/forms_v1.py", ["HealthFindingForm"],
                           PrimaryModelForm=BaseForm, HealthFinding=object)["HealthFindingForm"]()
        form.save_m2m = Mock()
        return form, instance

    def test_metadata_edit_preserves_resolution_time(self):
        form, instance = self.editor("resolved")
        original = instance.resolved_at
        form.save()
        self.assertEqual(instance.resolved_at, original)
        instance.save.assert_called_once()

    def test_reopening_clears_resolution_time(self):
        form, instance = self.editor("active")
        form.save()
        self.assertIsNone(instance.resolved_at)
