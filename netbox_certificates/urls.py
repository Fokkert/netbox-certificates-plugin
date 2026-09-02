from django.urls import path

from . import bulk_export, models, views

app_name = "netbox_certificates"

urlpatterns = (
    path("certificates/", views.CertificateListView.as_view(), name="certificate_list"),
    path("certificates/export-material/", bulk_export.BulkMaterialExportView.as_view(), {"kind": "certificate"}, name="certificate_material_export"),
    path("certificates/edit/", views.CertificateBulkEditView.as_view(), name="certificate_bulk_edit"),
    path("certificates/rename/", views.CertificateBulkRenameView.as_view(), name="certificate_bulk_rename"),
    path("certificates/delete/", views.CertificateBulkDeleteView.as_view(), name="certificate_bulk_delete"),
    path("certificates/add/", views.CertificateEditView.as_view(), name="certificate_add"),
    path("certificates/<int:pk>/", views.CertificateView.as_view(), name="certificate"),
    path("certificates/<int:pk>/edit/", views.CertificateEditView.as_view(), name="certificate_edit"),
    path("certificates/<int:pk>/delete/", views.CertificateDeleteView.as_view(), name="certificate_delete"),
    path("certificates/<int:pk>/changelog/", views.ArtifactObjectChangeLogView.as_view(), name="certificate_changelog", kwargs={"model": models.Certificate}),

    # CertificateAuthority remains the internal root-identity/chain-resolution model,
    # but the dedicated web UI has been retired. Legacy URLs redirect to Certificates.
    path("certificate-authorities/", bulk_export.CertificateAuthorityLegacyRedirectView.as_view(), name="certificateauthority_list"),
    path("certificate-authorities/<int:pk>/", bulk_export.CertificateAuthorityLegacyRedirectView.as_view(), name="certificateauthority"),
    path("certificate-authorities/<int:pk>/edit/", bulk_export.CertificateAuthorityLegacyRedirectView.as_view(), name="certificateauthority_edit"),
    path("certificate-authorities/<int:pk>/delete/", bulk_export.CertificateAuthorityLegacyRedirectView.as_view(), name="certificateauthority_delete"),
    path("certificate-authorities/<int:pk>/changelog/", bulk_export.CertificateAuthorityLegacyRedirectView.as_view(), name="certificateauthority_changelog"),

    path("private-keys/", views.PrivateKeyListView.as_view(), name="privatekey_list"),
    path("private-keys/export-material/", bulk_export.BulkMaterialExportView.as_view(), {"kind": "privatekey"}, name="privatekey_material_export"),
    path("private-keys/edit/", views.PrivateKeyBulkEditView.as_view(), name="privatekey_bulk_edit"),
    path("private-keys/rename/", views.PrivateKeyBulkRenameView.as_view(), name="privatekey_bulk_rename"),
    path("private-keys/delete/", views.PrivateKeyBulkDeleteView.as_view(), name="privatekey_bulk_delete"),
    path("private-keys/add/", views.PrivateKeyEditView.as_view(), name="privatekey_add"),
    path("private-keys/<int:pk>/", views.PrivateKeyView.as_view(), name="privatekey"),
    path("private-keys/<int:pk>/edit/", views.PrivateKeyEditView.as_view(), name="privatekey_edit"),
    path("private-keys/<int:pk>/delete/", views.PrivateKeyDeleteView.as_view(), name="privatekey_delete"),
    path("private-keys/<int:pk>/changelog/", views.ArtifactObjectChangeLogView.as_view(), name="privatekey_changelog", kwargs={"model": models.PrivateKey}),

    path("csrs/", views.CSRListView.as_view(), name="csr_list"),
    path("csrs/export-material/", bulk_export.BulkMaterialExportView.as_view(), {"kind": "csr"}, name="csr_material_export"),
    path("csrs/edit/", views.CSRBulkEditView.as_view(), name="csr_bulk_edit"),
    path("csrs/rename/", views.CSRBulkRenameView.as_view(), name="csr_bulk_rename"),
    path("csrs/delete/", views.CSRBulkDeleteView.as_view(), name="csr_bulk_delete"),
    path("csrs/add/", views.CSREditView.as_view(), name="csr_add"),
    path("csrs/generate/", views.CSRGenerateView.as_view(), name="csr_generate"),
    path("csrs/<int:pk>/", views.CSRView.as_view(), name="csr"),
    path("csrs/<int:pk>/edit/", views.CSREditView.as_view(), name="csr_edit"),
    path("csrs/<int:pk>/delete/", views.CSRDeleteView.as_view(), name="csr_delete"),
    path("csrs/<int:pk>/changelog/", views.ArtifactObjectChangeLogView.as_view(), name="csr_changelog", kwargs={"model": models.CSR}),

    path("bundles/", views.BundleListView.as_view(), name="bundle_list"),
    path("bundles/export-material/", bulk_export.BulkMaterialExportView.as_view(), {"kind": "bundle"}, name="bundle_material_export"),
    path("bundles/edit/", views.BundleBulkEditView.as_view(), name="bundle_bulk_edit"),
    path("bundles/rename/", views.BundleBulkRenameView.as_view(), name="bundle_bulk_rename"),
    path("bundles/delete/", views.BundleBulkDeleteView.as_view(), name="bundle_bulk_delete"),
    path("bundles/<int:pk>/", views.BundleView.as_view(), name="bundle"),
    path("bundles/<int:pk>/edit/", views.BundleEditView.as_view(), name="bundle_edit"),
    path("bundles/<int:pk>/delete/", views.BundleDeleteView.as_view(), name="bundle_delete"),
    path("bundles/<int:pk>/export/", views.BundleExportView.as_view(), name="bundle_export"),
    path("bundles/<int:pk>/changelog/", views.ArtifactObjectChangeLogView.as_view(), name="bundle_changelog", kwargs={"model": models.Bundle}),

    path("groups/", views.ArtifactGroupListView.as_view(), name="artifactgroup_list"),
    path("groups/edit/", views.ArtifactGroupBulkEditView.as_view(), name="artifactgroup_bulk_edit"),
    path("groups/rename/", views.ArtifactGroupBulkRenameView.as_view(), name="artifactgroup_bulk_rename"),
    path("groups/delete/", views.ArtifactGroupBulkDeleteView.as_view(), name="artifactgroup_bulk_delete"),
    path("groups/add/", views.ArtifactGroupEditView.as_view(), name="artifactgroup_add"),
    path("groups/<int:pk>/", views.ArtifactGroupView.as_view(), name="artifactgroup"),
    path("groups/<int:pk>/edit/", views.ArtifactGroupEditView.as_view(), name="artifactgroup_edit"),
    path("groups/<int:pk>/delete/", views.ArtifactGroupDeleteView.as_view(), name="artifactgroup_delete"),
    path("groups/<int:pk>/changelog/", views.ArtifactObjectChangeLogView.as_view(), name="artifactgroup_changelog", kwargs={"model": models.ArtifactGroup}),

    path("expiration-dashboard/", views.ExpirationDashboardView.as_view(), name="expiration_dashboard"),
    path("inventory/", views.InventoryView.as_view(), name="inventory"),
    path("expiration-alerts/", views.ExpirationAlertsView.as_view(), name="expiration_alerts"),
    path("import/", views.UnifiedImportView.as_view(), name="import_objects"),
    path("download/<str:kind>/<int:pk>/", views.DownloadArtifactView.as_view(), name="download"),
    path("link/<str:kind>/<int:pk>/", views.ArtifactLinkCreateView.as_view(), name="link_add"),
    path("links/<int:pk>/remove/", views.ArtifactLinkRemoveView.as_view(), name="link_remove"),
)
