from netbox.api.viewsets import NetBoxModelViewSet
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from .exports import MaterialExportMixin, MetadataExportMixin

from ..filtersets_v1 import (
    AlertChannelFilterSet,
    AlertEventFilterSet,
    AlertRuleFilterSet,
    HealthFindingFilterSet,
    ObjectLinkFilterSet,
    ServiceFilterSet,
)
from ..artifact_filtersets_v1 import (
    ArtifactGroupV1FilterSet,
    BundleV1FilterSet,
    CertificateV1FilterSet,
    CSRV1FilterSet,
    PrivateKeyV1FilterSet,
)
from ..models import Certificate
from ..models_v1 import AlertChannel, AlertEvent, AlertRule, HealthFinding, ObjectLink, Service
from ..permissions import action_queryset
from .views import (
    _require_sensitive_token,
    UnifiedImportAPIView,
    ArtifactGroupViewSet as LegacyArtifactGroupViewSet,
    BundleViewSet as LegacyBundleViewSet,
    CertificateViewSet as LegacyCertificateViewSet,
    CSRViewSet as LegacyCSRViewSet,
    PrivateKeyViewSet as LegacyPrivateKeyViewSet,
)
from .v1_serializers import (
    CACertificateSerializer,
    AlertChannelSerializer,
    AlertEventSerializer,
    AlertRuleSerializer,
    HealthFindingSerializer,
    ObjectLinkSerializer,
    ServiceSerializer,
)


class ArtifactGroupViewSet(MetadataExportMixin, LegacyArtifactGroupViewSet):
    filterset_class = ArtifactGroupV1FilterSet


class CertificateViewSet(MaterialExportMixin, LegacyCertificateViewSet):
    filterset_class = CertificateV1FilterSet


class PrivateKeyViewSet(MaterialExportMixin, LegacyPrivateKeyViewSet):
    filterset_class = PrivateKeyV1FilterSet


class CSRViewSet(MaterialExportMixin, LegacyCSRViewSet):
    filterset_class = CSRV1FilterSet


class BundleViewSet(MaterialExportMixin, LegacyBundleViewSet):
    filterset_class = BundleV1FilterSet


class CertificateAuthorityViewSet(CertificateViewSet):
    """Public CA API: real Certificate objects with X.509 CA=true."""

    queryset = Certificate.objects.filter(is_ca=True)
    serializer_class = CACertificateSerializer
    ca_only = True


class CAImportAPIView(UnifiedImportAPIView):
    ca_only = True


class ServiceViewSet(MetadataExportMixin, NetBoxModelViewSet):
    queryset = Service.objects.all()
    serializer_class = ServiceSerializer
    filterset_class = ServiceFilterSet


class ObjectLinkViewSet(MetadataExportMixin, NetBoxModelViewSet):
    queryset = ObjectLink.objects.select_related("source_type", "target_type")
    serializer_class = ObjectLinkSerializer
    filterset_class = ObjectLinkFilterSet

    def get_queryset(self):
        queryset = super().get_queryset()
        if self.request.method in {"PATCH", "PUT", "DELETE"}:
            queryset = queryset.filter(automatic=False)
        return queryset

    def update(self, request, *args, **kwargs):
        if self.get_object().automatic:
            return Response({"detail": "Automatic cryptographic links are managed by reconciliation."}, status=409)
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        if self.get_object().automatic:
            return Response({"detail": "Automatic cryptographic links are managed by reconciliation."}, status=409)
        return super().partial_update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        if self.get_object().automatic:
            return Response({"detail": "Automatic cryptographic links are managed by reconciliation."}, status=409)
        return super().destroy(request, *args, **kwargs)


class HealthFindingViewSet(MetadataExportMixin, NetBoxModelViewSet):
    queryset = HealthFinding.objects.select_related("object_type", "related_type")
    serializer_class = HealthFindingSerializer
    filterset_class = HealthFindingFilterSet

    def create(self, request, *args, **kwargs):
        return Response({"detail": "Health findings are created by a health scan."}, status=405)

    @action(detail=False, methods=["post"], url_path="refresh", permission_classes=[IsAuthenticated])
    def refresh_health(self, request):
        _require_sensitive_token(request)
        if not (
            request.user.is_superuser
            or request.user.has_perm("netbox_certificates.run_healthscan_healthfinding")
        ):
            return Response({"detail": "Health-scan permission is required."}, status=403)
        from ..services.health_v1 import refresh_health_findings
        return Response(refresh_health_findings())

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def acknowledge(self, request, pk=None):
        _require_sensitive_token(request)
        finding = action_queryset(HealthFinding, request.user, "acknowledge").filter(pk=pk).first()
        if finding is None:
            return Response({"detail": "Acknowledge permission is required for this finding."}, status=403)
        finding.status = "acknowledged"
        finding.resolved_at = None
        finding.save()
        return Response(self.get_serializer(finding).data)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def ignore(self, request, pk=None):
        _require_sensitive_token(request)
        finding = action_queryset(HealthFinding, request.user, "ignore").filter(pk=pk).first()
        if finding is None:
            return Response({"detail": "Ignore permission is required for this finding."}, status=403)
        finding.status = "ignored"
        finding.resolved_at = None
        finding.save()
        return Response(self.get_serializer(finding).data)

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def resolve(self, request, pk=None):
        _require_sensitive_token(request)
        from django.utils import timezone
        finding = action_queryset(HealthFinding, request.user, "resolve").filter(pk=pk).first()
        if finding is None:
            return Response({"detail": "Resolve permission is required for this finding."}, status=403)
        finding.status = "resolved"
        finding.resolved_at = timezone.now()
        finding.save()
        return Response(self.get_serializer(finding).data)


class AlertChannelViewSet(MetadataExportMixin, NetBoxModelViewSet):
    queryset = AlertChannel.objects.all()
    serializer_class = AlertChannelSerializer
    filterset_class = AlertChannelFilterSet

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def test(self, request, pk=None):
        _require_sensitive_token(request)
        channel = action_queryset(AlertChannel, request.user, "test").filter(pk=pk).first()
        if channel is None:
            return Response({"detail": "Alert-channel test permission is required for this channel."}, status=403)
        from ..services.alerts_v1 import send_test_channel
        try:
            sample = send_test_channel(channel)
        except Exception as exc:
            return Response({"detail": f"Test failed ({type(exc).__name__}). Check destination, credentials, and TLS settings."}, status=400)
        return Response({"detail": f"Test {channel.channel_type} sent successfully.", "sample": sample})


class AlertRuleViewSet(MetadataExportMixin, NetBoxModelViewSet):
    queryset = AlertRule.objects.all()
    serializer_class = AlertRuleSerializer
    filterset_class = AlertRuleFilterSet

    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def test(self, request, pk=None):
        _require_sensitive_token(request)
        rule = action_queryset(AlertRule, request.user, "test").filter(pk=pk).first()
        if rule is None:
            return Response({"detail": "Alert-rule test permission is required for this rule."}, status=403)
        from ..services.alerts_v1 import dispatch_alerts
        return Response(dispatch_alerts(rule_ids=[rule.pk], bypass_cooldown=True))


class AlertEventViewSet(MetadataExportMixin, NetBoxModelViewSet):
    queryset = AlertEvent.objects.select_related("rule", "channel", "finding")
    serializer_class = AlertEventSerializer
    filterset_class = AlertEventFilterSet

    def create(self, request, *args, **kwargs):
        return Response({"detail": "Delivery events are generated by the alert engine."}, status=405)
