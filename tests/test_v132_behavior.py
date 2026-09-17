"""Render the real inventory selector to catch checkbox and bound-form regressions."""
import ast
from html.parser import HTMLParser
import unittest

import django
from django import forms
from django.template import Context, Engine

from test_revision_behavior import ROOT, definitions


class SelectorParser(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.inputs = []
        self.labels = []
        self.feed(html)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "input":
            self.inputs.append(attrs)
        elif tag == "label":
            self.labels.append(attrs)


class InventorySelectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        django.setup()

    @staticmethod
    def form_class():
        source = ast.parse((ROOT / "netbox_certificates/inventory_export.py").read_text(encoding="utf-8"))
        labels = next(ast.literal_eval(n.value) for n in source.body
                      if isinstance(n, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "TYPE_LABELS" for t in n.targets))
        return definitions("netbox_certificates/inventory_export.py", ["InventoryExportForm"],
                           forms=forms, TYPE_LABELS=labels)["InventoryExportForm"]

    @staticmethod
    def render(form):
        engine = Engine(dirs=[str(ROOT / "netbox_certificates/templates")])
        return engine.get_template("netbox_certificates/inc/inventory_types.html").render(Context({"form": form}))

    def test_each_type_has_a_styled_checkbox_and_linked_label(self):
        form = self.form_class()()
        parsed = SelectorParser(self.render(form))
        self.assertEqual(len(parsed.inputs), len(form.fields["types"].choices))
        self.assertEqual({i["id"] for i in parsed.inputs}, {label["for"] for label in parsed.labels})
        for item in parsed.inputs:
            self.assertEqual(item["type"], "checkbox")
            self.assertEqual(item["name"], "types")
            self.assertIn("form-check-input", item["class"].split())
        self.assertEqual({i["value"] for i in parsed.inputs if "checked" in i},
                         {"certificate", "privatekey", "csr", "bundle"})

    def test_bound_selection_is_retained_after_export_error(self):
        form = self.form_class()({"types": ["service", "artifactgroup"]})
        self.assertTrue(form.is_valid())
        form.add_error(None, "Export failed. Try again.")
        parsed = SelectorParser(self.render(form))
        self.assertEqual({i["value"] for i in parsed.inputs if "checked" in i}, {"service", "artifactgroup"})

    def test_empty_or_unknown_selection_is_rejected_and_error_rendered(self):
        for data in ({}, {"types": ["unknown"]}):
            with self.subTest(data=data):
                form = self.form_class()(data)
                self.assertFalse(form.is_valid())
                html = self.render(form)
                self.assertIn('id="export-types-errors" role="alert"', html)
                self.assertIn('aria-describedby="export-types-help export-types-errors"', html)
                self.assertFalse(any("checked" in i for i in SelectorParser(html).inputs))
