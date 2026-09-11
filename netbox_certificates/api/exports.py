from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import extend_schema
from rest_framework import serializers
from rest_framework.decorators import action
from rest_framework.exceptions import MethodNotAllowed, ValidationError
from rest_framework.permissions import IsAuthenticated

from ..bulk_export import BulkMaterialExportView
from ..export_v1 import MetadataArchiveExportView
from ..services.pkcs12_export import PFXExportError
from .views import _require_sensitive_token


class MaterialExportOptionsSerializer(serializers.Serializer):
    include_chain = serializers.BooleanField(default=True)
    export_pfx = serializers.BooleanField(default=False)
    protect_pfx = serializers.BooleanField(default=True)
    password = serializers.CharField(required=False, allow_blank=True, write_only=True, trim_whitespace=False, default="")

    def validate(self, attrs):
        if attrs["export_pfx"] and attrs["protect_pfx"] and not attrs["password"]:
            raise serializers.ValidationError({"password": "Provide a PFX password or set protect_pfx=false."})
        return attrs


class MetadataExportMixin:
    @extend_schema(responses=OpenApiTypes.BINARY)
    @action(detail=False, methods=["get"], url_path="export-archive", permission_classes=[IsAuthenticated])
    def export_archive(self, request):
        return MetadataArchiveExportView().get(request, self.queryset.model._meta.model_name)


class MaterialExportMixin:
    @extend_schema(request=MaterialExportOptionsSerializer, responses=OpenApiTypes.BINARY)
    @action(detail=False, methods=["get", "post"], url_path="export-material", permission_classes=[IsAuthenticated])
    def export_material(self, request):
        _require_sensitive_token(request)
        kind = self.queryset.model._meta.model_name
        if kind == "bundle" and request.method != "POST":
            raise MethodNotAllowed(request.method, detail="POST bundle export options as JSON.")
        options = MaterialExportOptionsSerializer(data=request.data if request.method == "POST" else {})
        options.is_valid(raise_exception=True)
        view = BulkMaterialExportView()
        view.bundle_options = options.validated_data
        if getattr(self, "ca_only", False):
            view.forced_filters = {"is_ca": "true"}
        try:
            return view._export(request, kind)
        except PFXExportError as exc:
            raise ValidationError({"detail": str(exc)}) from exc
