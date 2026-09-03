from django.urls import path

from . import bulk_export, export_v1, models, views, views_v1

app_name = "netbox_certificates"

urlpatterns = (
    # OVERVIEW
    path("expiration-dashboard/", views.ExpirationDashboardView.as_view(), name="expiration_dashboard"),
    path("certificate-authorities/", views_v1.CertificateAuthorityListView.as_view(), name="certificateauthority_list"),
    path("certificate-authorities/export-material/", bulk_export.CertificateAuthorityMaterialExportView.as_view(), name="certificateauthority_material_export"),
    path("vault/", views_v1.CryptographicVaultView.as_view(), name="vault"),
    path("health/", views_v1.HealthFindingListView.as_view(), name="health"),
    path("health/refresh/", views_v1.HealthRefreshView.as_view(), name="health_refresh"),
    path("health/<int:pk>/", views_v1.HealthFindingView.as_view(), name="healthfinding"),
    path("health/edit/", views_v1.HealthFindingBulkEditView.as_view(), name="healthfinding_bulk_edit"),
    path("health/delete/", views_v1.HealthFindingBulkDeleteView.as_view(), name="healthfinding_bulk_delete"),
    path("health/export-archive/", export_v1.MetadataArchiveExportView.as_view(), {"kind": "healthfinding"}, name="healthfinding_archive_export"),

    # Certificate policies are managed from Health and Validity.
    path("health/policies/", views_v1.CertificatePolicyListView.as_view(), name="certificatepolicy_list"),
    path("health/policies/add/", views_v1.CertificatePolicyEditView.as_view(), name="certificatepolicy_add"),
    path("health/policies/edit/", views_v1.CertificatePolicyBulkEditView.as_view(), name="certificatepolicy_bulk_edit"),
    path("health/policies/rename/", views_v1.CertificatePolicyBulkRenameView.as_view(), name="certificatepolicy_bulk_rename"),
    path("health/policies/delete/", views_v1.CertificatePolicyBulkDeleteView.as_view(), name="certificatepolicy_bulk_delete"),
    path("health/policies/export-archive/", export_v1.MetadataArchiveExportView.as_view(), {"kind": "certificatepolicy"}, name="certificatepolicy_archive_export"),
    path("health/policies/<int:pk>/", views_v1.CertificatePolicyView.as_view(), name="certificatepolicy"),
    path("health/policies/<int:pk>/edit/", views_v1.CertificatePolicyEditView.as_view(), name="certificatepolicy_edit"),
    path("health/policies/<int:pk>/delete/", views_v1.CertificatePolicyDeleteView.as_view(), name="certificatepolicy_delete"),

    # INVENTORY: Groups
    path("groups/", views_v1.ArtifactGroupTreeListView.as_view(), name="artifactgroup_list"),
    path("groups/export-archive/", export_v1.MetadataArchiveExportView.as_view(), {"kind": "artifactgroup"}, name="artifactgroup_archive_export"),
    path("groups/edit/", views.ArtifactGroupBulkEditView.as_view(), name="artifactgroup_bulk_edit"),
    path("groups/rename/", views.ArtifactGroupBulkRenameView.as_view(), name="artifactgroup_bulk_rename"),
    path("groups/delete/", views.ArtifactGroupBulkDeleteView.as_view(), name="artifactgroup_bulk_delete"),
    path("groups/add/", views.ArtifactGroupEditView.as_view(), name="artifactgroup_add"),
    path("groups/<int:pk>/", views.ArtifactGroupView.as_view(), name="artifactgroup"),
    path("groups/<int:pk>/edit/", views.ArtifactGroupEditView.as_view(), name="artifactgroup_edit"),
    path("groups/<int:pk>/delete/", views.ArtifactGroupDeleteView.as_view(), name="artifactgroup_delete"),
    path("groups/<int:pk>/changelog/", views.ArtifactObjectChangeLogView.as_view(), name="artifactgroup_changelog", kwargs={"model": models.ArtifactGroup}),

    # INVENTORY: Services
    path("services/", views_v1.ServiceListView.as_view(), name="service_list"),
    path("services/add/", views_v1.ServiceEditView.as_view(), name="service_add"),
    path("services/edit/", views_v1.ServiceBulkEditView.as_view(), name="service_bulk_edit"),
    path("services/rename/", views_v1.ServiceBulkRenameView.as_view(), name="service_bulk_rename"),
    path("services/delete/", views_v1.ServiceBulkDeleteView.as_view(), name="service_bulk_delete"),
    path("services/export-archive/", export_v1.MetadataArchiveExportView.as_view(), {"kind": "service"}, name="service_archive_export"),
    path("services/<int:pk>/", views_v1.ServiceView.as_view(), name="service"),
    path("services/<int:pk>/edit/", views_v1.ServiceEditView.as_view(), name="service_edit"),
    path("services/<int:pk>/delete/", views_v1.ServiceDeleteView.as_view(), name="service_delete"),

    # INVENTORY: Bundles
    path("bundles/", views_v1.BundleListView.as_view(), name="bundle_list"),
    path("bundles/export-material/", bulk_export.BulkMaterialExportView.as_view(), {"kind": "bundle"}, name="bundle_material_export"),
    path("bundles/edit/", views.BundleBulkEditView.as_view(), name="bundle_bulk_edit"),
    path("bundles/rename/", views.BundleBulkRenameView.as_view(), name="bundle_bulk_rename"),
    path("bundles/delete/", views.BundleBulkDeleteView.as_view(), name="bundle_bulk_delete"),
    path("bundles/<int:pk>/", views.BundleView.as_view(), name="bundle"),
    path("bundles/<int:pk>/edit/", views.BundleEditView.as_view(), name="bundle_edit"),
    path("bundles/<int:pk>/delete/", views.BundleDeleteView.as_view(), name="bundle_delete"),
    path("bundles/<int:pk>/export/", bulk_export.SingleBundleArchiveExportView.as_view(), name="bundle_export"),
    path("bundles/<int:pk>/changelog/", views.ArtifactObjectChangeLogView.as_view(), name="bundle_changelog", kwargs={"model": models.Bundle}),

    # INVENTORY: Certificates
    path("certificates/", views_v1.CertificateListView.as_view(), name="certificate_list"),
    path("certificates/export-material/", bulk_export.BulkMaterialExportView.as_view(), {"kind": "certificate"}, name="certificate_material_export"),
    path("certificates/edit/", views.CertificateBulkEditView.as_view(), name="certificate_bulk_edit"),
    path("certificates/rename/", views.CertificateBulkRenameView.as_view(), name="certificate_bulk_rename"),
    path("certificates/delete/", views.CertificateBulkDeleteView.as_view(), name="certificate_bulk_delete"),
    path("certificates/add/", views.CertificateEditView.as_view(), name="certificate_add"),
    path("certificates/<int:pk>/", views.CertificateView.as_view(), name="certificate"),
    path("certificates/<int:pk>/edit/", views.CertificateEditView.as_view(), name="certificate_edit"),
    path("certificates/<int:pk>/delete/", views.CertificateDeleteView.as_view(), name="certificate_delete"),
    path("certificates/<int:pk>/changelog/", views.ArtifactObjectChangeLogView.as_view(), name="certificate_changelog", kwargs={"model": models.Certificate}),

    # INVENTORY: Private Keys
    path("private-keys/", views_v1.PrivateKeyListView.as_view(), name="privatekey_list"),
    path("private-keys/export-material/", bulk_export.BulkMaterialExportView.as_view(), {"kind": "privatekey"}, name="privatekey_material_export"),
    path("private-keys/edit/", views.PrivateKeyBulkEditView.as_view(), name="privatekey_bulk_edit"),
    path("private-keys/rename/", views.PrivateKeyBulkRenameView.as_view(), name="privatekey_bulk_rename"),
    path("private-keys/delete/", views.PrivateKeyBulkDeleteView.as_view(), name="privatekey_bulk_delete"),
    path("private-keys/add/", views.PrivateKeyEditView.as_view(), name="privatekey_add"),
    path("private-keys/<int:pk>/", views.PrivateKeyView.as_view(), name="privatekey"),
    path("private-keys/<int:pk>/edit/", views.PrivateKeyEditView.as_view(), name="privatekey_edit"),
    path("private-keys/<int:pk>/delete/", views.PrivateKeyDeleteView.as_view(), name="privatekey_delete"),
    path("private-keys/<int:pk>/changelog/", views.ArtifactObjectChangeLogView.as_view(), name="privatekey_changelog", kwargs={"model": models.PrivateKey}),

    # INVENTORY: CSRs
    path("csrs/", views_v1.CSRListView.as_view(), name="csr_list"),
    path("csrs/export-material/", bulk_export.BulkMaterialExportView.as_view(), {"kind": "csr"}, name="csr_material_export"),
    path("csrs/edit/", views.CSRBulkEditView.as_view(), name="csr_bulk_edit"),
    path("csrs/rename/", views.CSRBulkRenameView.as_view(), name="csr_bulk_rename"),
    path("csrs/delete/", views.CSRBulkDeleteView.as_view(), name="csr_bulk_delete"),
    path("csrs/add/", views.CSREditView.as_view(), name="csr_add"),
    path("csrs/<int:pk>/", views.CSRView.as_view(), name="csr"),
    path("csrs/<int:pk>/edit/", views.CSREditView.as_view(), name="csr_edit"),
    path("csrs/<int:pk>/delete/", views.CSRDeleteView.as_view(), name="csr_delete"),
    path("csrs/<int:pk>/changelog/", views.ArtifactObjectChangeLogView.as_view(), name="csr_changelog", kwargs={"model": models.CSR}),

    # Object links: generic many-to-many-style associations to native NetBox objects.
    path("links/", views_v1.ObjectLinkListView.as_view(), name="objectlink_list"),
    path("links/add/", views_v1.ObjectLinkEditView.as_view(), name="objectlink_add"),
    path("links/edit/", views_v1.ObjectLinkBulkEditView.as_view(), name="objectlink_bulk_edit"),
    path("links/delete/", views_v1.ObjectLinkBulkDeleteView.as_view(), name="objectlink_bulk_delete"),
    path("links/export-archive/", export_v1.MetadataArchiveExportView.as_view(), {"kind": "objectlink"}, name="objectlink_archive_export"),
    path("links/<int:pk>/", views_v1.ObjectLinkView.as_view(), name="objectlink"),
    path("links/<int:pk>/edit/", views_v1.ObjectLinkEditView.as_view(), name="objectlink_edit"),
    path("links/<int:pk>/delete/", views_v1.ObjectLinkDeleteView.as_view(), name="objectlink_delete"),

    # OPERATIONS
    path("import/", views.UnifiedImportView.as_view(), name="import_objects"),
    path("generate-csr/", views.CSRGenerateView.as_view(), name="csr_generate"),
    path("alerts/", views_v1.AlertRuleListView.as_view(), name="alertrule_list"),
    path("alerts/add/", views_v1.AlertRuleEditView.as_view(), name="alertrule_add"),
    path("alerts/edit/", views_v1.AlertRuleBulkEditView.as_view(), name="alertrule_bulk_edit"),
    path("alerts/rename/", views_v1.AlertRuleBulkRenameView.as_view(), name="alertrule_bulk_rename"),
    path("alerts/delete/", views_v1.AlertRuleBulkDeleteView.as_view(), name="alertrule_bulk_delete"),
    path("alerts/export-archive/", export_v1.MetadataArchiveExportView.as_view(), {"kind": "alertrule"}, name="alertrule_archive_export"),
    path("alerts/<int:pk>/", views_v1.AlertRuleView.as_view(), name="alertrule"),
    path("alerts/<int:pk>/edit/", views_v1.AlertRuleEditView.as_view(), name="alertrule_edit"),
    path("alerts/<int:pk>/test/", views_v1.AlertRuleTestView.as_view(), name="alertrule_test"),
    path("alerts/<int:pk>/delete/", views_v1.AlertRuleDeleteView.as_view(), name="alertrule_delete"),

    path("alerts/channels/", views_v1.AlertChannelListView.as_view(), name="alertchannel_list"),
    path("alerts/channels/add/", views_v1.AlertChannelEditView.as_view(), name="alertchannel_add"),
    path("alerts/channels/edit/", views_v1.AlertChannelBulkEditView.as_view(), name="alertchannel_bulk_edit"),
    path("alerts/channels/rename/", views_v1.AlertChannelBulkRenameView.as_view(), name="alertchannel_bulk_rename"),
    path("alerts/channels/delete/", views_v1.AlertChannelBulkDeleteView.as_view(), name="alertchannel_bulk_delete"),
    path("alerts/channels/export-archive/", export_v1.MetadataArchiveExportView.as_view(), {"kind": "alertchannel"}, name="alertchannel_archive_export"),
    path("alerts/channels/<int:pk>/", views_v1.AlertChannelView.as_view(), name="alertchannel"),
    path("alerts/channels/<int:pk>/edit/", views_v1.AlertChannelEditView.as_view(), name="alertchannel_edit"),
    path("alerts/channels/<int:pk>/test/", views_v1.AlertChannelTestView.as_view(), name="alertchannel_test"),
    path("alerts/channels/<int:pk>/delete/", views_v1.AlertChannelDeleteView.as_view(), name="alertchannel_delete"),

    path("alerts/events/", views_v1.AlertEventListView.as_view(), name="alertevent_list"),
    path("alerts/events/edit/", views_v1.AlertEventBulkEditView.as_view(), name="alertevent_bulk_edit"),
    path("alerts/events/delete/", views_v1.AlertEventBulkDeleteView.as_view(), name="alertevent_bulk_delete"),
    path("alerts/events/export-archive/", export_v1.MetadataArchiveExportView.as_view(), {"kind": "alertevent"}, name="alertevent_archive_export"),
    path("alerts/events/<int:pk>/", views_v1.AlertEventView.as_view(), name="alertevent"),

    # Existing secure single-file material download.
    path("download/<str:kind>/<int:pk>/", views.DownloadArtifactView.as_view(), name="download"),
)
