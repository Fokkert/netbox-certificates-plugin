from drf_spectacular.utils import extend_schema
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ..preferences import INTERVALS, PREFERENCE_FIELDS, PreferencesForm, get_preferences
from .views import _require_sensitive_token


class PreferencesSerializer(serializers.Serializer):
    health_scan_enabled = serializers.BooleanField(required=False)
    health_scan_interval_minutes = serializers.ChoiceField(choices=INTERVALS, required=False)
    alert_interval_minutes = serializers.ChoiceField(choices=INTERVALS, required=False)
    expiration_warning_days = serializers.IntegerField(min_value=30, max_value=3650, required=False)
    import_chain_default = serializers.BooleanField(required=False)
    preserve_archive_default = serializers.BooleanField(required=False)
    csr_rsa_bits = serializers.ChoiceField(choices=[2048, 3072, 4096, 8192], required=False)
    last_health_scan = serializers.DateTimeField(read_only=True, allow_null=True)
    last_alert_evaluation = serializers.DateTimeField(read_only=True, allow_null=True)


class PreferencesAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if not request.user.is_superuser:
            raise PermissionDenied("Plugin preferences require a NetBox superuser.")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            _require_sensitive_token(request)

    @extend_schema(responses=PreferencesSerializer)
    def get(self, request):
        return Response(PreferencesSerializer(get_preferences()).data)

    @extend_schema(request=PreferencesSerializer, responses=PreferencesSerializer)
    def patch(self, request):
        config = get_preferences()
        serializer = PreferencesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = {name: getattr(config, name) for name in PREFERENCE_FIELDS}
        data.update(serializer.validated_data)
        form = PreferencesForm(data, instance=config)
        if not form.is_valid():
            raise serializers.ValidationError(dict(form.errors))
        return Response(PreferencesSerializer(form.save()).data)

    @extend_schema(request=PreferencesSerializer, responses=PreferencesSerializer)
    def put(self, request):
        return self.patch(request)
