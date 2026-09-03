from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODELS_FILE = ROOT / "netbox_certificates" / "models_v1.py"
MIGRATIONS_DIR = ROOT / "netbox_certificates" / "migrations"
EXPECTED_TAG_MODEL = "extras.Tag"


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _keywords(call: ast.Call) -> dict[str, ast.AST]:
    return {
        keyword.arg: keyword.value
        for keyword in call.keywords
        if keyword.arg is not None
    }


class NetBox45TagMigrationStateContractTests(unittest.TestCase):
    def test_all_serialized_taggable_managers_have_explicit_tag_model(self):
        failures: list[str] = []

        for migration_path in sorted(MIGRATIONS_DIR.glob("*.py")):
            tree = ast.parse(
                migration_path.read_text(encoding="utf-8"),
                filename=str(migration_path),
            )

            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if _call_name(node) != "TaggableManager":
                    continue

                keywords = _keywords(node)
                to_value = keywords.get("to")

                if to_value is None:
                    failures.append(
                        f"{migration_path.name}:{node.lineno}: missing to="
                    )
                    continue

                try:
                    value = ast.literal_eval(to_value)
                except Exception:
                    failures.append(
                        f"{migration_path.name}:{node.lineno}: non-literal to="
                    )
                    continue

                if value != EXPECTED_TAG_MODEL:
                    failures.append(
                        f"{migration_path.name}:{node.lineno}: to={value!r}"
                    )

        self.assertFalse(
            failures,
            "Every serialized NetBox TaggableManager must explicitly target "
            f"{EXPECTED_TAG_MODEL!r} for migration-state rendering:\n"
            + "\n".join(failures),
        )

    def test_runtime_service_tags_targets_netbox_tag_model(self):
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

        tags_call = None

        for statement in service.body:
            if not isinstance(statement, ast.Assign):
                continue

            if not any(
                isinstance(target, ast.Name) and target.id == "tags"
                for target in statement.targets
            ):
                continue

            self.assertIsInstance(statement.value, ast.Call)
            tags_call = statement.value
            break

        self.assertIsNotNone(
            tags_call,
            "Service must explicitly override PrimaryModel.tags",
        )

        keywords = _keywords(tags_call)

        self.assertEqual(
            ast.literal_eval(keywords["to"]),
            EXPECTED_TAG_MODEL,
        )
        self.assertEqual(
            ast.literal_eval(keywords["through"]),
            "extras.TaggedItem",
        )
        self.assertIn("related_name", keywords)


if __name__ == "__main__":
    unittest.main()
