from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BulkOperationsContractTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_material_export_routes_exist_for_all_crypto_object_pages(self):
        urls = self.read("netbox_certificates/urls.py")
        for route_name in (
            "certificate_material_export",
            "privatekey_material_export",
            "csr_material_export",
            "bundle_material_export",
        ):
            self.assertIn(f'name="{route_name}"', urls)

    def test_bulk_export_preserves_custom_permission_boundaries(self):
        export = self.read("netbox_certificates/bulk_export.py")
        self.assertIn('"certificate": {', export)
        self.assertIn('"privatekey": {', export)
        self.assertIn('"csr": {', export)
        self.assertIn('"bundle": {', export)
        self.assertIn('"action": "download"', export)
        self.assertIn('"action": "export"', export)
        self.assertIn("action_queryset(config[\"model\"], request.user, config[\"action\"])", export)
        self.assertIn("decrypt_private_key", export)
        self.assertIn('response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"', export)

    def test_list_pages_expose_material_export_controls(self):
        expected = {
            "certificate_list.html": "certificate_material_export",
            "privatekey_list.html": "privatekey_material_export",
            "csr_list.html": "csr_material_export",
            "bundle_list.html": "bundle_material_export",
        }
        for template, route_name in expected.items():
            text = self.read(f"netbox_certificates/templates/netbox_certificates/{template}")
            self.assertIn(route_name, text)
            self.assertIn("Export Material", text)
            self.assertIn("request.GET.urlencode", text)

    def test_certificate_authority_ui_is_retired_but_identity_mechanism_remains(self):
        navigation = self.read("netbox_certificates/navigation.py")
        urls = self.read("netbox_certificates/urls.py")
        views = self.read("netbox_certificates/views.py")
        models = self.read("netbox_certificates/models.py")
        api_urls = self.read("netbox_certificates/api/urls.py")
        service = self.read("netbox_certificates/services/certificate_authorities.py")

        self.assertNotIn('link_text="Certificate Authorities"', navigation)
        self.assertIn("CertificateAuthorityLegacyRedirectView", urls)
        self.assertNotIn("class CertificateAuthorityListView", views)
        self.assertNotIn("class CertificateAuthorityView", views)
        self.assertNotIn("class CertificateAuthorityEditView", views)
        self.assertNotIn("class CertificateAuthorityDeleteView", views)
        self.assertFalse((ROOT / "netbox_certificates/templates/netbox_certificates/certificate_authority.html").exists())
        self.assertFalse((ROOT / "netbox_certificates/templates/netbox_certificates/certificate_authority_list.html").exists())
        self.assertIn("class CertificateAuthority(PrimaryModel)", models)
        self.assertIn("authority = models.ForeignKey(", models)
        self.assertIn('router.register("certificate-authorities", CertificateAuthorityViewSet)', api_urls)
        self.assertIn("def root_certificate_for", service)

    def test_unified_import_can_batch_archives_and_loose_bundle_identities(self):
        unified = self.read("netbox_certificates/services/unified_import.py")
        self.assertIn("archive_items = [item for item in items if is_archive(item.data)]", unified)
        self.assertIn("with transaction.atomic():", unified)
        self.assertIn("def _loose_bundle_groups(parsed_records):", unified)
        self.assertIn("public-key fingerprint", unified.lower())
        self.assertIn("bulk-bundle-", unified)


if __name__ == "__main__":
    unittest.main()
