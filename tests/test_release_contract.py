from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ReleaseContractTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_release_metadata_is_1_0_3(self):
        pyproject = self.read("pyproject.toml")
        plugin = self.read("netbox-plugin.yaml")
        config = self.read("netbox_certificates/__init__.py")
        self.assertIn('version = "1.0.3"', pyproject)
        self.assertIn("version: 1.0.3", plugin)
        self.assertIn('version = "1.0.3"', config)
        self.assertIn('min_version = "4.5.9"', config)
        self.assertIn('max_version = "4.5.10"', config)

    def test_exact_navigation_groups_and_labels(self):
        nav = self.read("netbox_certificates/navigation.py")
        expected = (
            '"Overview"',
            'link_text="Expiration Dashboard"',
            'link_text="Certificate Authorities"',
            'link_text="Cryptographic Vault"',
            'link_text="Health and Validity"',
            '"Inventory"',
            'link_text="Groups"',
            'link_text="Services"',
            'link_text="Bundles"',
            'link_text="Certificates"',
            'link_text="Private Keys"',
            'link_text="CSRs"',
            '"Operations"',
            'link_text="Import Objects"',
            'link_text="Generate CSR"',
            'link_text="Alerts Configuration"',
        )
        for token in expected:
            self.assertIn(token, nav)

        self.assertNotIn("Expiration Alerts", nav)
        self.assertNotIn('link_text="Inventory"', nav)

    def test_breaking_ui_routes_do_not_keep_legacy_aliases(self):
        urls = self.read("netbox_certificates/urls.py")
        self.assertIn('path("vault/"', urls)
        self.assertIn('path("alerts/"', urls)
        self.assertIn('path("generate-csr/"', urls)
        self.assertNotIn('path("inventory/"', urls)
        self.assertNotIn('path("expiration-alerts/"', urls)
        self.assertNotIn('name="link_add"', urls)
        self.assertNotIn('name="link_remove"', urls)
        self.assertNotIn("LegacyRedirect", urls)
        self.assertNotIn("request-certificate", urls.lower())

    def test_models_are_integrated_into_normal_django_model_import(self):
        integrator = self.read("scripts/integrate_v1.py")
        self.assertIn("def integrate_models(repo: Path)", integrator)
        self.assertIn("from .models_v1 import", integrator)
        self.assertIn('"Service"', integrator)
        self.assertIn('"HealthFinding"', integrator)

    def test_old_public_models_are_private_in_1_0(self):
        models = self.read("netbox_certificates/models_v1.py")
        for name in (
            "_InternalCertificateAuthority",
            "_LegacyArtifactLink",
            "_LegacyExpiryAlertConfiguration",
            "_LegacyExpiryAlertEvent",
        ):
            self.assertIn(f"{name}._netbox_private = True", models)

    def test_graphql_omits_private_key_and_alert_secrets(self):
        graphql = self.read("netbox_certificates/graphql.py")
        self.assertIn("def _safe_fields(model):", graphql)
        self.assertIn("@strawberry_django.type(PrivateKey, fields=_safe_fields(PrivateKey))", graphql)
        self.assertIn("@strawberry_django.type(AlertChannel, fields=_safe_fields(AlertChannel))", graphql)
        for sensitive_name in (
            '"material"',
            '"encrypted_material"',
            '"smtp_password_encrypted"',
            '"webhook_url_encrypted"',
            '"webhook_headers_encrypted"',
        ):
            self.assertIn(sensitive_name, graphql)
        self.assertIn('if name in _SENSITIVE_FIELD_NAMES', graphql)
        self.assertIn('"encrypted" in name.lower()', graphql)
        self.assertIn('"password" in name.lower()', graphql)
        self.assertNotIn('fields="__all__"', graphql)


    def test_upgrade_docs_map_replaced_public_interfaces(self):
        readme = self.read("README.md")
        upgrade = self.read("UPGRADE.md")
        self.assertIn("NetBox Certificates Plugin", readme)
        self.assertIn("## API and URL changes", upgrade)
        self.assertIn("/inventory/", upgrade)
        self.assertIn("/vault/", upgrade)
        self.assertIn("object-links/", upgrade)


    def test_readme_is_product_focused(self):
        readme = self.read("README.md")
        for heading in (
            "## Features",
            "## Services",
            "## Health and Validity",
            "## Installation",
            "## Security",
        ):
            self.assertIn(heading, readme)
        self.assertIn("NetBox Certificates Plugin", readme)
        self.assertIn("netbox-certificates-plugin==1.0.3", readme)



if __name__ == "__main__":
    unittest.main()
