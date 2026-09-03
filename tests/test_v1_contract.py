from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class VersionOneFeatureContracts(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_service_is_first_class_and_many_to_many(self):
        models = self.read("netbox_certificates/models_v1.py")
        self.assertIn("class Service(PrimaryModel):", models)
        self.assertIn("deployment = models.CharField(", models)
        self.assertNotIn("class Deployment(", models)
        for relation in ("groups", "certificates", "private_keys", "csrs", "bundles"):
            self.assertIn(f"{relation} = models.ManyToManyField(", models)

    def test_service_deployment_allows_presets_and_custom_values(self):
        models = self.read("netbox_certificates/models_v1.py")
        forms = self.read("netbox_certificates/forms_v1.py")
        self.assertIn('default="Generic TLS Endpoint"', models)
        self.assertIn("class DeploymentTextInput", forms)
        self.assertIn('"Nginx"', forms)
        self.assertIn('"Kubernetes Ingress"', forms)
        self.assertIn("forms.CharField(required=True, widget=DeploymentTextInput())", forms)

    def test_generic_object_links_are_many_object_capable(self):
        models = self.read("netbox_certificates/models_v1.py")
        self.assertIn("class ObjectLink(PrimaryModel):", models)
        self.assertIn("GenericForeignKey", models)
        self.assertIn("source_type = models.ForeignKey(", models)
        self.assertIn("target_type = models.ForeignKey(", models)
        self.assertIn("issubclass(model, NetBoxModel)", models)
        self.assertIn("netbox_certificates_v1_objectlink_unique", models)

    def test_netbox_object_link_extensions_are_registered(self):
        extensions = self.read("netbox_certificates/template_content.py")
        for model in (
            '"dcim.device"',
            '"ipam.ipaddress"',
            '"virtualization.virtualmachine"',
            '"circuits.circuit"',
        ):
            self.assertIn(model, extensions)
        self.assertIn("ObjectLinksExtension", extensions)
        self.assertIn("ServiceAssignmentsExtension", extensions)

    def test_ca_page_and_api_use_actual_ca_certificates(self):
        views = self.read("netbox_certificates/views_v1.py")
        api = self.read("netbox_certificates/api/v1_views.py")
        self.assertIn("Certificate.objects.filter(is_ca=True)", views)
        self.assertIn("Certificate.objects.filter(is_ca=True)", api)

    def test_health_engine_covers_requested_problem_classes(self):
        health = self.read("netbox_certificates/services/health_v1.py")
        for code in (
            "CERT_EXPIRED",
            "AMBIGUOUS_ISSUER",
            "INVALID_PARENT_SIGNATURE",
            "CERTIFICATE_CHAIN_LOOP",
            "DUPLICATE_CERTIFICATE",
            "DUPLICATE_PRIVATE_KEY",
            "BUNDLE_PUBLIC_KEY_MISMATCH",
            "SERVICE_NAME_NOT_COVERED",
            "SERVICE_CERTIFICATE_KEY_MISMATCH",
            "PRIVATE_KEY_REUSED_ACROSS_SERVICES",
            "NON_WILDCARD_CERT_REUSED_ACROSS_SERVICES",
            "SINGLE_HOST_CERT_SHARED_ACROSS_SERVICES",
            "CERTIFICATE_POLICY_VIOLATION",
        ):
            self.assertIn(code, health)
        self.assertIn("verify_directly_issued_by", health)

    def test_alerts_are_generic_and_secrets_are_encrypted(self):
        models = self.read("netbox_certificates/models_v1.py")
        alerts = self.read("netbox_certificates/services/alerts_v1.py")
        secrets = self.read("netbox_certificates/services/secret_v1.py")
        self.assertIn("class AlertRule(PrimaryModel):", models)
        self.assertIn("expiration_days", models)
        self.assertIn("object_types", models)
        self.assertIn("tag_names", models)
        self.assertIn("owner_ids", models)
        self.assertIn("policies = models.ManyToManyField", models)
        self.assertIn("smtp_password_encrypted", models)
        self.assertIn("webhook_url_encrypted", models)
        self.assertIn("dispatch_alerts", alerts)
        self.assertIn("Fernet", secrets)

    def test_groups_have_expandable_tree(self):
        template = self.read("netbox_certificates/templates/netbox_certificates/artifactgroup_tree_list.html")
        self.assertIn("aria-expanded", template)
        self.assertIn("localStorage", template)
        self.assertIn("block.super", template)

    def test_search_indexes_cover_inventory_and_crypto_identifiers(self):
        search = self.read("netbox_certificates/search.py")
        for klass in (
            "ArtifactGroupIndex",
            "ServiceIndex",
            "CertificateIndex",
            "PrivateKeyIndex",
            "CSRIndex",
            "BundleIndex",
            "CertificatePolicyIndex",
            "HealthFindingIndex",
        ):
            self.assertIn(f"class {klass}", search)
        self.assertIn("public_key_fingerprint", search)
        self.assertNotIn("encrypted_material", search)

    def test_migrations_are_present(self):
        for name in (
            "0014_certificate_management_v1.py",
            "0015_migrate_legacy_links.py",
            "0016_cleanup_pre_v1_permissions.py",
        ):
            self.assertTrue((ROOT / "netbox_certificates/migrations" / name).exists())


    def test_netbox_45_migration_uses_taggit_manager(self):
        migration = self.read("netbox_certificates/migrations/0014_certificate_management_v1.py")
        self.assertIn("import taggit.managers", migration)
        self.assertIn("taggit.managers.TaggableManager(", migration)
        self.assertNotIn("NetBoxTaggableManagerField", migration)
        self.assertNotIn("import netbox_certificates.models_v1", migration)

    def test_plugin_registers_public_models_at_ready_time(self):
        config = self.read("netbox_certificates/__init__.py")
        self.assertIn("model_is_public", config)
        self.assertIn("register_models", config)

    def test_v1_wrappers_keep_legacy_filter_forms_and_add_relationship_filters(self):
        views = self.read("netbox_certificates/views_v1.py")
        for name in (
            "CertificateListView",
            "PrivateKeyListView",
            "CSRListView",
            "BundleListView",
            "CertificateV1FilterForm",
            "PrivateKeyV1FilterForm",
            "CSRV1FilterForm",
            "BundleV1FilterForm",
        ):
            self.assertIn(f"class {name}", views)

    def test_single_bundle_multifile_export_uses_manifest(self):
        urls = self.read("netbox_certificates/urls.py")
        exporter = self.read("netbox_certificates/bulk_export.py")
        self.assertIn("SingleBundleArchiveExportView.as_view()", urls)
        self.assertIn("class SingleBundleArchiveExportView", exporter)
        self.assertIn('"manifest.json"', exporter)

    def test_object_links_require_public_netbox_models(self):
        models = self.read("netbox_certificates/models_v1.py")
        api = self.read("netbox_certificates/api/v1_serializers.py")
        self.assertIn("model_is_public(model)", models)
        self.assertIn("model_is_public(model)", api)



if __name__ == "__main__":
    unittest.main()
