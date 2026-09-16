from django.urls import path
from netbox.api.routers import NetBoxRouter
from .views import UnifiedImportAPIView
from .v1_urls import register_v1_routes
from .v1_views import CAImportAPIView
from .inventory import InventoryExportAPIView
from .preferences import PreferencesAPIView
from .alert_settings import AlertSettingsAPIView, AlertSettingsTestAPIView
app_name = 'netbox_certificates'
router = NetBoxRouter()
register_v1_routes(router)
urlpatterns = [
    path("preferences/", PreferencesAPIView.as_view(), name="preferences"),
    path("export-inventory/", InventoryExportAPIView.as_view(), name="export-inventory"),
    path('import-objects/', UnifiedImportAPIView.as_view(), name='import-objects'),
    path('certificate-authorities/import/', CAImportAPIView.as_view(), name='import-ca-certificates'),
    path('alert-settings/', AlertSettingsAPIView.as_view(), name='alert-settings'),
    path('alert-settings/test-email/', AlertSettingsTestAPIView.as_view(test_method='email'), name='alert-settings-test-email'),
    path('alert-settings/test-webhook/', AlertSettingsTestAPIView.as_view(test_method='webhook'), name='alert-settings-test-webhook'),
] + router.urls
