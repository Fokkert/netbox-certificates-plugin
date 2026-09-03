from django.urls import path
from netbox.api.routers import NetBoxRouter
from .views import ArtifactGroupViewSet, ArtifactLinkViewSet, BundleViewSet, CertificateAuthorityViewSet, CertificateViewSet, CSRViewSet, ExpiryAlertConfigurationViewSet, ExpiryAlertEventViewSet, PrivateKeyViewSet, UnifiedImportAPIView
from .v1_urls import register_v1_routes
app_name = 'netbox_certificates'
router = NetBoxRouter()
register_v1_routes(router)
urlpatterns = router.urls + [path('import-objects/', UnifiedImportAPIView.as_view(), name='import-objects')]
