from drf_spectacular.utils import extend_schema
from drf_spectacular.types import OpenApiTypes
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView

from ..inventory_export import TYPE_LABELS, export_inventory
from ..services.encryption import PrivateKeyEncryptionError
from .views import _require_sensitive_token


class InventoryExportSerializer(serializers.Serializer):
    types = serializers.ListField(child=serializers.ChoiceField(choices=list(TYPE_LABELS)), allow_empty=False)


class InventoryExportAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=InventoryExportSerializer, responses=OpenApiTypes.BINARY)
    def post(self, request):
        _require_sensitive_token(request)
        serializer = InventoryExportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            return export_inventory(request, list(dict.fromkeys(serializer.validated_data["types"])))
        except PrivateKeyEncryptionError as exc:
            raise ValidationError({"detail": "Stored key material could not be decrypted. No archive was returned."}) from exc
