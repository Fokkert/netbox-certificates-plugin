from __future__ import annotations

import ast
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODELS_FILE = ROOT / "netbox_certificates" / "models_v1.py"
MIGRATIONS_DIR = ROOT / "netbox_certificates" / "migrations"
EXPECTED_RELATED_NAME = "netbox_certificates_service_tagged+"


class NetBox45ServiceTagsContractTests(unittest.TestCase):
    def test_service_overrides_inherited_tags_with_unique_related_name(self):
        tree = ast.parse(MODELS_FILE.read_text(encoding="utf-8"), filename=str(MODELS_FILE))
        service = next(
            (node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Service"),
            None,
        )
        self.assertIsNotNone(service, "Service model was not found")

        tags_call = None
        for statement in service.body:
            if not isinstance(statement, ast.Assign):
                continue
            if not any(isinstance(target, ast.Name) and target.id == "tags" for target in statement.targets):
                continue
            self.assertIsInstance(statement.value, ast.Call)
            tags_call = statement.value
            break

        self.assertIsNotNone(tags_call, "Service must explicitly override inherited PrimaryModel.tags")
        self.assertIsInstance(tags_call.func, ast.Name)
        self.assertEqual(tags_call.func.id, "TaggableManager")

        keywords = {kw.arg: kw.value for kw in tags_call.keywords if kw.arg is not None}
        self.assertEqual(ast.literal_eval(keywords["related_name"]), EXPECTED_RELATED_NAME)
        self.assertEqual(ast.literal_eval(keywords["through"]), "extras.TaggedItem")

    def test_state_migration_preserves_service_tags_related_name(self):
        migrations = sorted(MIGRATIONS_DIR.glob("0018_*.py"))
        self.assertEqual(len(migrations), 1, "Expected exactly one 0018 migration")

        text = migrations[0].read_text(encoding="utf-8")
        self.assertIn("SeparateDatabaseAndState", text)
        self.assertIn('model_name="service"', text)
        self.assertIn('name="tags"', text)
        self.assertIn(f'related_name="{EXPECTED_RELATED_NAME}"', text)
        self.assertIn("database_operations=[]", text)


if __name__ == "__main__":
    unittest.main()
