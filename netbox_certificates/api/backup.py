from drf_spectacular.utils import extend_schema
from drf_spectacular.types import OpenApiTypes
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ..backup import read_upload
from ..services.backup import BackupError
from ..services.metadata_import import import_metadata
from .views import _require_superuser_token






class MetadataImportSerializer(serializers.Serializer):
    upload = serializers.FileField()
    kind = serializers.ChoiceField(choices=["service", "artifactgroup"], required=False)






class MetadataImportAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=MetadataImportSerializer, responses=OpenApiTypes.OBJECT)
    def post(self, request):
        _require_superuser_token(request)
        serializer = MetadataImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            return Response(import_metadata(read_upload(serializer.validated_data["upload"]), request.user,
                                            kind=serializer.validated_data.get("kind")))
        except BackupError as exc:
            raise ValidationError(str(exc)) from exc
