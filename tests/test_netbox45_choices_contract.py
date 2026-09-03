from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHOICES_FILE = ROOT / "netbox_certificates" / "choices_v1.py"


class NetBox45ChoiceSetContractTests(unittest.TestCase):
    def test_keyed_choicesets_use_list_for_choices(self):
        tree = ast.parse(
            CHOICES_FILE.read_text(encoding="utf-8"),
            filename=str(CHOICES_FILE),
        )

        checked = []

        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue

            has_key = False
            choices_value = None

            for statement in node.body:
                if not isinstance(statement, ast.Assign):
                    continue

                for target in statement.targets:
                    if isinstance(target, ast.Name) and target.id == "key":
                        has_key = True
                    if isinstance(target, ast.Name) and target.id == "CHOICES":
                        choices_value = statement.value

            if has_key:
                checked.append(node.name)
                self.assertIsNotNone(
                    choices_value,
                    f"{node.name} defines key but has no CHOICES assignment",
                )
                self.assertIsInstance(
                    choices_value,
                    ast.List,
                    f"{node.name}.CHOICES must be a list for NetBox 4.5 compatibility",
                )

        self.assertGreaterEqual(
            len(checked),
            8,
            "Expected the v1 module to contain the keyed ChoiceSet classes.",
        )


if __name__ == "__main__":
    unittest.main()
