from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "netbox_certificates"


class ReleaseContractTests(unittest.TestCase):
    def read(self, relative):
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_version_and_compatibility(self):
        text = self.read("netbox_certificates/__init__.py")
        pyproject = self.read("pyproject.toml")
        plugin_manifest = self.read("netbox-plugin.yaml")

        self.assertIn('version = "0.4.11"', text)
        self.assertIn('version = "0.4.11"', pyproject)
        self.assertIn('version: 0.4.11', plugin_manifest)

        self.assertIn('min_version = "4.5.9"', text)
        self.assertIn('max_version = "4.5.10"', text)
        self.assertIn('netbox_min_version: 4.5.9', plugin_manifest)
        self.assertIn('netbox_max_version: 4.5.10', plugin_manifest)

        self.assertFalse(
            (ROOT / "deploy-from-tmp.sh").exists(),
            "Legacy manual deployment helper must not ship in the public repository.",
        )

    def test_bulk_edit_contract(self):
        forms = self.read("netbox_certificates/forms.py")
        views = self.read("netbox_certificates/views.py")
        urls = self.read("netbox_certificates/urls.py")
        for name in ("Certificate", "PrivateKey", "CSR", "Bundle", "ArtifactGroup"):
            self.assertRegex(forms, rf"class {name}BulkEditForm\(PrimaryModelBulkEditForm\)")
            self.assertRegex(views, rf"class {name}BulkEditView\(generic\.BulkEditView\)")
        self.assertIn('name="certificate_bulk_edit"', urls)
        self.assertIn('FieldSet("alert_trigger", "trigger_unit"', forms)

    def test_groups_are_simple_hierarchical_tree(self):
        models = self.read("netbox_certificates/models.py")
        forms = self.read("netbox_certificates/forms.py")
        tables = self.read("netbox_certificates/tables.py")
        api = self.read("netbox_certificates/api/serializers.py")
        navigation = self.read("netbox_certificates/navigation.py")
        self.assertIn('verbose_name = "group"', models)
        self.assertIn('related_name="children"', models)
        self.assertIn('verbose_name="parent group"', models)
        self.assertNotIn('child_groups = models.ManyToManyField(', models)
        self.assertIn('label="Members"', forms)
        self.assertIn('FieldSet("members", name="Members")', forms)
        self.assertIn('parent = serializers.PrimaryKeyRelatedField(', api)
        self.assertIn('members = serializers.SerializerMethodField()', api)
        self.assertIn('verbose_name="Members"', tables)
        self.assertIn('link_text="Groups"', navigation)
        self.assertNotIn('link_text="Object Groups"', navigation)

    def test_0012_converts_legacy_nested_groups(self):
        migration = self.read("netbox_certificates/migrations/0012_group_hierarchy_and_ui_labels.py")
        self.assertIn('("netbox_certificates", "0011_object_groups_and_certificate_authorities")', migration)
        self.assertIn('name="parent"', migration)
        self.assertIn('convert_group_membership_to_tree', migration)
        self.assertIn('name="child_groups"', migration)
        self.assertIn('migrations.RemoveField(', migration)
        self.assertIn('"verbose_name": "group"', migration)

    def test_certificate_authority_is_identity_model(self):
        models = self.read("netbox_certificates/models.py")
        views = self.read("netbox_certificates/views.py")
        tables = self.read("netbox_certificates/tables.py")
        api_urls = self.read("netbox_certificates/api/urls.py")
        self.assertIn("class CertificateAuthority(PrimaryModel)", models)
        self.assertIn("issuer_dn = models.TextField", models)
        self.assertIn("authority = models.ForeignKey(", models)
        self.assertIn("CertificateAuthorityEditView", views)
        self.assertNotIn("class CertificateAuthorityTable(CertificateTable)", tables)
        self.assertIn('router.register("certificate-authorities", CertificateAuthorityViewSet)', api_urls)

    def test_certificate_authority_standard_routes_exist(self):
        urls = self.read("netbox_certificates/urls.py")
        for name in (
            "certificateauthority_list",
            "certificateauthority",
            "certificateauthority_edit",
            "certificateauthority_delete",
            "certificateauthority_changelog",
        ):
            self.assertIn(f'name="{name}"', urls)


    def test_expiration_alert_configuration_api_queryset_is_ordered(self):
        views = self.read("netbox_certificates/api/views.py")
        block = views.split("class ExpiryAlertConfigurationViewSet", 1)[1].split("class ExpiryAlertEventViewSet", 1)[0]
        self.assertIn('ExpiryAlertConfiguration.objects.order_by("pk")', block)
        self.assertNotIn("ExpiryAlertConfiguration.objects.all()", block)

    def test_repeat_alert_mode_remains(self):
        alerts = self.read("netbox_certificates/services/alerts.py")
        models = self.read("netbox_certificates/models.py")
        self.assertIn("AlertRepeatModeChoices.WHILE_DUE", alerts)
        self.assertIn("alert_repeat_mode = models.CharField", models)

    def test_email_alerts_are_rich_and_batch_capable_without_visible_html_word(self):
        alerts = self.read("netbox_certificates/services/alerts.py")
        template = self.read("netbox_certificates/templates/netbox_certificates/expiration_alert_email.html")
        self.assertIn("certificates=None", alerts)
        self.assertIn("_attempt_email_batch", alerts)
        self.assertIn("_email_subject", alerts)
        self.assertIn('message.attach_alternative(html, "text/html")', alerts)
        self.assertIn("{% for report in reports %}", template)
        self.assertIn("Certificate identity", template)
        self.assertIn("NetBox context", template)
        visible_text = re.sub(r"<[^>]+>", " ", template)
        self.assertNotRegex(visible_text, r"\bHTML\b")
        self.assertNotIn("Object Groups", template)

    def test_expiry_alert_page_preserves_card_layout_and_smtp_security_group(self):
        template = self.read("netbox_certificates/templates/netbox_certificates/expiration_alerts.html")
        self.assertIn("mdi-email-outline", template)
        self.assertIn("mdi-webhook", template)
        self.assertIn("Worker Status", template)
        self.assertIn("Recent Deliveries", template)
        self.assertIn("form.alert_repeat_mode", template)
        self.assertIn("SMTP Security", template)
        self.assertIn("form.smtp_use_tls", template)
        self.assertIn("form.smtp_use_ssl", template)

    def test_webhook_dns_failure_is_specific(self):
        alerts = self.read("netbox_certificates/services/alerts.py")
        self.assertIn("import socket", alerts)
        self.assertIn("isinstance(reason, socket.gaierror)", alerts)
        self.assertIn("Webhook DNS lookup failed", alerts)
        self.assertIn("netbox-certificates-plugin/0.4.11", alerts)

    def test_inventory_colors_are_explicit_and_cache_busted(self):
        css = self.read("netbox_certificates/static/netbox_certificates/inventory.css")
        template = self.read("netbox_certificates/templates/netbox_certificates/inventory.html")
        self.assertIn("#8b5cf6", css)
        self.assertIn("#206bc4", css)
        self.assertIn("#d63939", css)
        self.assertIn("#2fb344", css)
        self.assertIn("background-color: rgba", css)
        self.assertIn("?v=0.4.11", template)
        self.assertNotIn("Object Groups:", template)

    def test_csr_generator_uses_netbox_table_style_san_list_and_two_extension_columns(self):
        template = self.read("netbox_certificates/templates/netbox_certificates/csr_generate.html")
        self.assertIn('class="table table-hover table-vcenter mb-0"', template)
        self.assertIn('<tbody id="san-editor"></tbody>', template)
        self.assertIn("document.createElement('tr')", template)
        self.assertIn('class="form-select san-type"', template)
        self.assertIn('class="form-control san-value"', template)
        self.assertIn('class="btn btn-sm btn-outline-danger san-remove"', template)
        self.assertIn("Subject Alternative Names (SANs)", template)
        self.assertIn("www.example.com", template)
        self.assertIn("192.0.2.10", template)
        self.assertIn("spiffe://example/service", template)
        self.assertIn('class="col-lg-6"', template)
        self.assertIn("Key Usage", template)
        self.assertIn("Extended Key Usage", template)
        self.assertIn("Generate CSR", template)
        self.assertIn("const reference = document.getElementById('id_rsa_signature')", template)
        self.assertIn("referenceInstance.constructor", template)
        self.assertIn("referenceInstance.settings", template)
        self.assertIn("Array.from(select.options)", template)
        self.assertIn("options: sanOptions", template)
        self.assertIn("items: [selectedValue]", template)
        self.assertIn("dropdownParent: 'body'", template)
        self.assertIn("instance.addOption(option)", template)
        self.assertIn("instance.setValue(selectedValue, true)", template)
        self.assertNotIn('class="table-responsive"', template)
        self.assertIn("new SelectConstructor(select", template)
        self.assertIn("enhanceSANType(typeSelect)", template)
        self.assertIn("typeSelect.tomselect.destroy()", template)

    def test_expiration_alert_fields_use_one_consistent_horizontal_grid(self):
        template = self.read("netbox_certificates/templates/netbox_certificates/expiration_alerts.html")
        # render_field already emits NetBox's horizontal field grid. Nesting those
        # grids inside unequal Bootstrap columns caused the 0.4.5 X/Y misalignment.
        self.assertNotIn('col-md-8">{% render_field form.smtp_host', template)
        self.assertNotIn('col-md-4">{% render_field form.smtp_port', template)
        self.assertNotIn('col-md-6">{% render_field form.smtp_username', template)
        self.assertNotIn('col-md-6">{% render_field form.email_from_address', template)
        for field in (
            "smtp_host", "smtp_port", "smtp_username", "smtp_password",
            "smtp_use_tls", "smtp_use_ssl", "email_from_address",
            "email_recipients", "include_superusers",
        ):
            self.assertIn(f"{{% render_field form.{field} %}}", template)

    def test_acronym_casing_in_key_user_interfaces(self):
        forms = self.read("netbox_certificates/forms.py")
        alert_template = self.read("netbox_certificates/templates/netbox_certificates/expiration_alerts.html")
        csr_template = self.read("netbox_certificates/templates/netbox_certificates/csr_generate.html")
        for required in ("SMTP host", "SMTP port", "SMTP username", "STARTTLS", "SSL/TLS", "Webhook URL"):
            self.assertIn(required, forms)
        self.assertIn("SMTP Security", alert_template)
        for required in ("CSR", "SANs", "X.509", "CA"):
            self.assertIn(required, csr_template)

    def test_unified_import_and_navigation_contract(self):
        urls = self.read("netbox_certificates/urls.py")
        navigation = self.read("netbox_certificates/navigation.py")
        self.assertIn('path("import/", views.UnifiedImportView.as_view()', urls)
        self.assertIn('link_text="Certificate Authorities"', navigation)
        self.assertIn('link_text="Groups"', navigation)
        operations = navigation.split('"Operations"', 1)[1]
        self.assertIn('link_text="Import Objects"', operations)
        self.assertIn('link_text="Generate CSR"', operations)
        self.assertIn('link_text="Expiration Alerts"', operations)

    def test_group_parent_choices_are_hierarchy_aware_and_owner_is_not_duplicated(self):
        forms = self.read("netbox_certificates/forms.py")
        self.assertIn("current_depth = len(self.instance.ancestor_ids())", forms)
        self.assertIn("len(candidate.ancestor_ids()) <= current_depth", forms)
        group_block = forms.split("class ArtifactGroupForm", 1)[1].split("class CertificateArtifactFilterForm", 1)[0]
        self.assertIn('FieldSet("name", "parent", "description", "tags", name="Group")', group_block)
        self.assertNotIn('FieldSet("name", "parent", "owner"', group_block)
        self.assertIn('fields = ("name", "parent", "owner", "description", "comments", "tags")', group_block)

    def test_groups_and_certificate_authorities_have_native_export(self):
        views = self.read("netbox_certificates/views.py")
        self.assertIn("class ArtifactGroupListView(generic.ObjectListView):\n    actions = (AddObject, BulkExport, BulkEdit, BulkRename, BulkDelete)", views)
        self.assertIn("class CertificateAuthorityListView(generic.ObjectListView):\n    actions = (BulkExport,)", views)

    def test_certificate_authorities_are_root_only(self):
        service = self.read("netbox_certificates/services/certificate_authorities.py")
        migration = self.read("netbox_certificates/migrations/0013_root_authorities_and_bundle_status.py")
        views = self.read("netbox_certificates/views.py")
        self.assertIn("def root_certificate_for", service)
        self.assertIn("parsed.subject != parsed.issuer", service)
        self.assertIn("parsed.verify_directly_issued_by(parsed)", service)
        self.assertIn("Intermediate issuer identities are no longer Certificate Authorities", migration)
        self.assertIn('certificates__subject=F("certificates__issuer")', views)

    def test_filter_forms_and_filtersets_cover_all_meaningful_fields(self):
        forms = self.read("netbox_certificates/forms.py")
        filtersets = self.read("netbox_certificates/filtersets.py")
        self.assertIn("class PrimaryModelFieldFilterSet(NetBoxModelFilterSet):", filtersets)
        self.assertIn("class GroupedPrimaryModelFilterSet(PrimaryModelFieldFilterSet):", filtersets)
        # Every PrimaryModel list exposes NetBox metadata/timestamps.
        for field in (
            "id", "owner", "description", "comments", "tags", "custom_field_data",
            "created", "created_after", "created_before", "last_updated", "last_updated_after", "last_updated_before",
        ):
            self.assertIn(field, forms)
            self.assertIn(field, filtersets)
        # Certificate fields.
        for field in (
            "name", "status", "source_filename", "source_format", "material",
            "fingerprint_sha256", "public_key_fingerprint", "serial_number", "subject", "issuer",
            "authority", "subject_alternative_names", "valid_from", "valid_from_after", "valid_from_before",
            "valid_to", "valid_to_after", "valid_to_before", "signature_algorithm", "key_type", "key_size",
            "curve", "is_ca", "parent_certificate", "supersedes", "alert_trigger", "trigger_unit", "groups",
        ):
            self.assertIn(field, forms)
            self.assertIn(field, filtersets)
        # Other model-specific fields and reverse relationships.
        for field in (
            "issuer_dn", "certificates", "material_sha256", "encrypted_on_import",
            "identity_fingerprint", "archive_format", "has_encrypted_archive", "import_report",
            "private_key", "csr", "chain_certificates", "parent", "children", "private_keys", "csrs", "bundles",
        ):
            self.assertIn(field, forms)
            self.assertIn(field, filtersets)

    def test_bundle_complete_requires_all_three_primary_objects(self):
        linker = self.read("netbox_certificates/services/linker.py")
        bundles = self.read("netbox_certificates/services/bundles.py")
        migration = self.read("netbox_certificates/migrations/0013_root_authorities_and_bundle_status.py")
        self.assertIn("wanted_status = BundleStatusChoices.COMPLETE if primary_count == 3 else BundleStatusChoices.PARTIAL", linker)
        self.assertIn("BundleStatusChoices.COMPLETE if len(members) == 3 else BundleStatusChoices.PARTIAL", linker)
        self.assertIn("BundleStatusChoices.COMPLETE if all((leaf_obj, key_obj, csr_obj)) else BundleStatusChoices.PARTIAL", bundles)
        self.assertIn("complete = all((bundle.certificate_id, bundle.private_key_id, bundle.csr_id))", migration)

    def test_expiration_alert_ui_is_ordered_and_renamed(self):
        template = self.read("netbox_certificates/templates/netbox_certificates/expiration_alerts.html")
        navigation = self.read("netbox_certificates/navigation.py")
        dashboard = self.read("netbox_certificates/templates/netbox_certificates/dashboard_widget.html")
        self.assertIn("Expiration Alerts", template)
        self.assertIn("Alert Policy", template)
        self.assertIn("SMTP Connection", template)
        self.assertIn("SMTP Security", template)
        self.assertIn("Delivery", template)
        self.assertIn("Connection", template)
        self.assertIn("Options", template)
        self.assertIn('link_text="Expiration Alerts"', navigation)
        self.assertNotIn("Open dashboard", dashboard)

    def test_unnecessary_import_guide_text_is_removed(self):
        import_template = self.read("netbox_certificates/templates/netbox_certificates/import_objects.html")
        self.assertNotIn("Upload one or more certificates", import_template)
        self.assertNotIn("alert alert-info", import_template)

    def test_retired_compatibility_routes_and_api_aliases_are_removed(self):
        urls = self.read("netbox_certificates/urls.py")
        navigation = self.read("netbox_certificates/navigation.py")
        api_urls = self.read("netbox_certificates/api/urls.py")
        api_views = self.read("netbox_certificates/api/views.py")
        serializers = self.read("netbox_certificates/api/serializers.py")
        self.assertIn('path("expiration-alerts/", views.ExpirationAlertsView.as_view(), name="expiration_alerts")', urls)
        self.assertNotIn('expiry-alerts/', urls)
        self.assertNotIn('name="expiry_alerts"', urls)
        self.assertNotIn('certificate_authority_list', urls)
        self.assertNotIn('LegacyBundleImportRedirectView', self.read("netbox_certificates/views.py"))
        self.assertNotIn('bundle_import', urls)
        self.assertNotIn('bundle_add', urls)
        self.assertIn('plugins:netbox_certificates:expiration_alerts', navigation)
        self.assertNotIn('plugins:netbox_certificates:expiry_alerts', navigation)
        self.assertIn('router.register("expiration-alert-configurations"', api_urls)
        self.assertIn('router.register("expiration-alert-events"', api_urls)
        self.assertNotIn('expiry-alert-configurations', api_urls)
        self.assertNotIn('expiry-alert-events', api_urls)
        self.assertNotIn('url_path="import-archive"', api_views)
        self.assertNotIn('compatibility field', api_views)
        self.assertIn('request.FILES.getlist("files")', api_views)
        self.assertIn('url_path="expiration-summary"', api_views)
        self.assertNotIn('url_path="expiry-summary"', api_views)
        self.assertIn('expiration-alert-configuration-detail', serializers)
        self.assertIn('expiration-alert-event-detail', serializers)

    def test_partial_bundle_imports_are_allowed_and_labeled_partial(self):
        unified = self.read("netbox_certificates/services/unified_import.py")
        bundles = self.read("netbox_certificates/services/bundles.py")
        linker = self.read("netbox_certificates/services/linker.py")
        self.assertIn('if distinct_primary_types < 2:', unified)
        self.assertIn('if len(primary_items) < 2:', bundles)
        self.assertIn('BundleStatusChoices.COMPLETE if all((leaf_obj, key_obj, csr_obj)) else BundleStatusChoices.PARTIAL', bundles)
        self.assertIn('wanted_status = BundleStatusChoices.COMPLETE if primary_count == 3 else BundleStatusChoices.PARTIAL', linker)

    def test_certificate_and_csr_material_are_prepared_before_netbox_model_validation(self):
        serializers = self.read("netbox_certificates/api/serializers.py")
        cert_block = serializers.split("class CertificateSerializer", 1)[1].split("class PrivateKeySerializer", 1)[0]
        csr_block = serializers.split("class CSRSerializer", 1)[1].split("class BundleSerializer", 1)[0]
        for block in (cert_block, csr_block):
            self.assertIn('attrs = self._prepare(attrs)', block)
            self.assertIn('return super().validate(attrs)', block)
            self.assertLess(block.index('attrs = self._prepare(attrs)'), block.index('return super().validate(attrs)'))
        self.assertNotIn('attrs = super().validate(attrs)\n        if self.instance is None and not material', cert_block)
        self.assertNotIn('material = attrs.pop("material", None); attrs = super().validate(attrs)', csr_block)

    def test_unified_import_client_validation_uses_http_400_contract(self):
        views = self.read("netbox_certificates/api/views.py")
        block = views.split("class UnifiedImportAPIView", 1)[1]
        self.assertIn("ValidationError", views)
        self.assertIn('raise ValidationError({"files": ["Multipart field \'files\' is required."]})', block)
        self.assertIn('raise ValidationError({"files": [f"Combined upload is too large', block)
        self.assertIn('except UnifiedImportError as exc:', block)
        self.assertIn('raise ValidationError({"files": [str(exc)]}) from exc', block)
        self.assertNotIn('except UnifiedImportError as exc: raise APIException(str(exc)) from exc', block)

    def test_artifactgroup_route_contract(self):
        ui_urls = self.read("netbox_certificates/urls.py")
        api_urls = self.read("netbox_certificates/api/urls.py")
        serializers = self.read("netbox_certificates/api/serializers.py")
        self.assertIn('name="artifactgroup_list"', ui_urls)
        self.assertIn('name="artifactgroup"', ui_urls)
        self.assertIn('router.register("groups", ArtifactGroupViewSet)', api_urls)
        self.assertIn('artifactgroup-detail', serializers)
        self.assertIn('privatekey-detail', serializers)

    def test_templates_reference_existing_plugin_routes(self):
        urls = self.read("netbox_certificates/urls.py")
        names = set(re.findall(r'name="([^"]+)"', urls))
        for template in (PKG / "templates" / "netbox_certificates").glob("*.html"):
            text = template.read_text(encoding="utf-8")
            for route in re.findall(r"plugins:netbox_certificates:([A-Za-z0-9_-]+)", text):
                self.assertIn(route, names, f"{template.name} references missing route {route}")


if __name__ == "__main__":
    unittest.main()
