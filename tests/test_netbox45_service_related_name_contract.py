from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODELS_FILE = ROOT / "netbox_certificates" / "models_v1.py"
MIGRATIONS_DIR = ROOT / "netbox_certificates" / "migrations"
EXPECTED_RELATED_NAME = "%(app_label)s_%(model_name)s_set"


class NetBox45ServiceRelatedNameContractTests(unittest.TestCase):
    def test_service_uses_unique_default_related_name(self):
        tree = ast.parse(
            MODELS_FILE.read_text(encoding="utf-8"),
            filename=str(MODELS_FILE),
        )

        service = next(
            (
                node
                for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == "Service"
            ),
            None,
        )
        self.assertIsNotNone(service, "Service model was not found")

        meta = next(
            (
                node
                for node in service.body
                if isinstance(node, ast.ClassDef) and node.name == "Meta"
            ),
            None,
        )
        self.assertIsNotNone(meta, "Service.Meta was not found")

        value = None
        for statement in meta.body:
            if not isinstance(statement, ast.Assign):
                continue
            for target in statement.targets:
                if isinstance(target, ast.Name) and target.id == "default_related_name":
                    value = ast.literal_eval(statement.value)

        self.assertEqual(
            value,
            EXPECTED_RELATED_NAME,
            "Service must namespace inherited reverse relations so they do not "
            "collide with NetBox core ipam.Service.",
        )

    def test_state_migration_preserves_unique_default_related_name(self):
        migrations = sorted(MIGRATIONS_DIR.glob("0017_*.py"))
        self.assertEqual(
            len(migrations),
            1,
            "Expected exactly one 0017 migration.",
        )

        text = migrations[0].read_text(encoding="utf-8")
        self.assertIn('name="service"', text)
        self.assertIn(
            f'"default_related_name": "{EXPECTED_RELATED_NAME}"',
            text,
        )


if __name__ == "__main__":
    unittest.main()
