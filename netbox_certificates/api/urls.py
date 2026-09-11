from django.urls import path
from netbox.api.routers import NetBoxRouter
from .views import ArtifactGroupViewSet, ArtifactLinkViewSet, BundleViewSet, CertificateAuthorityViewSet, CertificateViewSet, CSRViewSet, ExpiryAlertConfigurationViewSet, ExpiryAlertEventViewSet, PrivateKeyViewSet, UnifiedImportAPIView
from .v1_urls import register_v1_routes
from .v1_views import CAImportAPIView
from .alert_settings import AlertSettingsAPIView, AlertSettingsTestAPIView
app_name = 'netbox_certificates'
router = NetBoxRouter()
register_v1_routes(router)
urlpatterns = [
    path('import-objects/', UnifiedImportAPIView.as_view(), name='import-objects'),
    path('certificate-authorities/import/', CAImportAPIView.as_view(), name='import-ca-certificates'),
    path('alert-settings/', AlertSettingsAPIView.as_view(), name='alert-settings'),
    path('alert-settings/test-email/', AlertSettingsTestAPIView.as_view(test_method='email'), name='alert-settings-test-email'),
    path('alert-settings/test-webhook/', AlertSettingsTestAPIView.as_view(test_method='webhook'), name='alert-settings-test-webhook'),
] + router.urls
