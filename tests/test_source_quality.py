"""Catch missing imports in complete modules, beyond isolated behavior tests."""
import ast
import unittest
from pathlib import Path

from pyflakes.api import checkPath
from pyflakes.reporter import Reporter
from pyflakes.messages import UndefinedName, ImportStarUsage


class UndefinedNameReporter(Reporter):
    def __init__(self):
        self.failures = []

    def flake(self, message):
        if isinstance(message, (UndefinedName, ImportStarUsage)):
            self.failures.append(str(message))

    def syntaxError(self, filename, message, lineno, offset, text):
        self.failures.append(f"{filename}:{lineno}: {message}")

    def unexpectedError(self, filename, message):
        self.failures.append(f"{filename}: {message}")


class SourceQuality(unittest.TestCase):
    def test_url_view_references_exist(self):
        root = Path(__file__).resolve().parents[1] / "netbox_certificates"
        modules = {}
        for name in ("views", "views_v1", "models", "bulk_export", "export_v1"):
            tree = ast.parse((root / f"{name}.py").read_text(encoding="utf-8"))
            modules[name] = {node.name for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))}
            for node in tree.body:
                if isinstance(node, ast.ImportFrom):
                    modules[name].update(alias.asname or alias.name for alias in node.names)
        routes = ast.parse((root / "urls.py").read_text(encoding="utf-8"))
        for node in ast.walk(routes):
            if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in modules:
                with self.subTest(module=node.value.id, name=node.attr):
                    self.assertIn(node.attr, modules[node.value.id])

    def test_complete_modules_have_no_undefined_names(self):
        reporter = UndefinedNameReporter()
        root = Path(__file__).resolve().parents[1] / "netbox_certificates"
        for path in root.rglob("*.py"):
            checkPath(str(path), reporter)
        self.assertEqual(reporter.failures, [])
