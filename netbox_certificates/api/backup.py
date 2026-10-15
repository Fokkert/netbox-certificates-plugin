from drf_spectacular.utils import extend_schema
from drf_spectacular.types import OpenApiTypes
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ..backup import backup_response, read_upload
from ..services.backup import BackupError, CONFIRMATION, create_backup, restore_backup
from ..services.metadata_import import import_metadata
from .views import _require_superuser_token


class BackupExportSerializer(serializers.Serializer):
    password = serializers.CharField(required=False, allow_blank=True, default="", max_length=1024, write_only=True)


class BackupRestoreSerializer(BackupExportSerializer):
    upload = serializers.FileField()
    confirmation = serializers.ChoiceField(choices=[CONFIRMATION])


class MetadataImportSerializer(serializers.Serializer):
    upload = serializers.FileField()


class BackupExportAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=BackupExportSerializer, responses=OpenApiTypes.BINARY)
    def post(self, request):
        _require_superuser_token(request)
        serializer = BackupExportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        password = serializer.validated_data["password"]
        try:
            return backup_response(create_backup(request.user, password), password)
        except ValueError as exc:
            raise ValidationError("Backup could not be created. Check configured encryption and size limits.") from exc


class BackupRestoreAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=BackupRestoreSerializer, responses=OpenApiTypes.OBJECT)
    def post(self, request):
        _require_superuser_token(request)
        serializer = BackupRestoreSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        values = serializer.validated_data
        try:
            return Response(restore_backup(read_upload(values["upload"]), request.user, values["confirmation"], values["password"]))
        except BackupError as exc:
            raise ValidationError(str(exc)) from exc


class MetadataImportAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(request=MetadataImportSerializer, responses=OpenApiTypes.OBJECT)
    def post(self, request):
        _require_superuser_token(request)
        serializer = MetadataImportSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        try:
            return Response(import_metadata(read_upload(serializer.validated_data["upload"]), request.user))
        except BackupError as exc:
            raise ValidationError(str(exc)) from exc
