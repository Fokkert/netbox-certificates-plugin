from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BulkOperationsContractTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_material_routes_exist_for_crypto_lists_and_ca(self):
        urls = self.read("netbox_certificates/urls.py")
        for name in (
            "certificate_material_export",
            "privatekey_material_export",
            "csr_material_export",
            "bundle_material_export",
            "certificateauthority_material_export",
        ):
            self.assertIn(f'name="{name}"', urls)

    def test_export_filter_bug_is_fixed_by_allowlisting_filterset_keys(self):
        exporter = self.read("netbox_certificates/bulk_export.py")
        self.assertIn("allowed = set(filterset_class.base_filters.keys())", exporter)
        self.assertIn("for key in allowed:", exporter)
        self.assertIn("request.GET.getlist(key)", exporter)
        self.assertIn('{"filter", "filter_id"}', exporter)
        self.assertNotIn("filterset_class(request.GET or None", exporter)

    def test_material_export_starts_with_action_restricted_queryset(self):
        exporter = self.read("netbox_certificates/bulk_export.py")
        self.assertIn('action_queryset(config["model"], request.user, config["action"])', exporter)
        self.assertIn("decrypt_private_key", exporter)
        self.assertIn('"action": "download"', exporter)
        self.assertIn('"action": "export"', exporter)

    def test_multi_file_exports_have_manifest_and_checksums(self):
        exporter = self.read("netbox_certificates/bulk_export.py")
        metadata = self.read("netbox_certificates/export_v1.py")
        for text in (exporter, metadata):
            self.assertIn('"manifest.json"', text)
            self.assertIn("sha256", text.lower())
            self.assertIn('"plugin_version": "1.0.0"', text)

    def test_sensitive_archive_headers_remain(self):
        exporter = self.read("netbox_certificates/bulk_export.py")
        self.assertIn('response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"', exporter)
        self.assertIn('response["Pragma"] = "no-cache"', exporter)
        self.assertIn('response["X-Content-Type-Options"] = "nosniff"', exporter)

    def test_new_lists_use_native_bulk_capable_generic_views(self):
        views = self.read("netbox_certificates/views_v1.py")
        for view_name in (
            "ServiceBulkEditView",
            "ServiceBulkDeleteView",
            "CertificatePolicyBulkEditView",
            "CertificatePolicyBulkDeleteView",
            "ObjectLinkBulkEditView",
            "ObjectLinkBulkDeleteView",
            "AlertRuleBulkEditView",
            "AlertRuleBulkDeleteView",
        ):
            self.assertIn(f"class {view_name}", views)

    def test_crypto_list_templates_keep_custom_export_controls(self):
        for template in (
            "certificate_list.html",
            "privatekey_list.html",
            "csr_list.html",
            "bundle_list.html",
        ):
            text = self.read(f"netbox_certificates/templates/netbox_certificates/{template}")
            self.assertIn("Export Material", text)


if __name__ == "__main__":
    unittest.main()
