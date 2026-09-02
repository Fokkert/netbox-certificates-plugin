from django.urls import path
from netbox.api.routers import NetBoxRouter
from .views import ArtifactGroupViewSet, ArtifactLinkViewSet, BundleViewSet, CertificateAuthorityViewSet, CertificateViewSet, CSRViewSet, ExpiryAlertConfigurationViewSet, ExpiryAlertEventViewSet, PrivateKeyViewSet, UnifiedImportAPIView

app_name = "netbox_certificates"
router = NetBoxRouter()
router.register("certificates", CertificateViewSet)
router.register("certificate-authorities", CertificateAuthorityViewSet)
router.register("private-keys", PrivateKeyViewSet)
router.register("csrs", CSRViewSet)
router.register("bundles", BundleViewSet)
router.register("groups", ArtifactGroupViewSet)
router.register("artifact-links", ArtifactLinkViewSet, basename="artifact-link")
router.register("expiration-alert-configurations", ExpiryAlertConfigurationViewSet, basename="expiration-alert-configuration")
router.register("expiration-alert-events", ExpiryAlertEventViewSet, basename="expiration-alert-event")
urlpatterns = router.urls + [path("import-objects/", UnifiedImportAPIView.as_view(), name="import-objects")]
