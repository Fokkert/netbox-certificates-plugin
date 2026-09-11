"""The same alert configuration and validation used by the settings page."""
from django import forms
from django.core.exceptions import ValidationError as DjangoValidationError
from drf_spectacular.utils import extend_schema
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ..alert_settings import AlertSettingsForm
from ..models_v1 import AlertSettings
from ..services.alerts_v1 import send_test_channel
from ..services.secret_v1 import SecretConfigurationError
from .views import _require_sensitive_token


SECRET_FIELDS = {"smtp_password", "webhook_url", "webhook_headers"}


class AlertSettingsSerializer(serializers.Serializer):
    def get_fields(self):
        fields = {}
        for name, field in AlertSettingsForm().fields.items():
            options = {"required": False, "label": field.label, "help_text": field.help_text,
                       "write_only": name in SECRET_FIELDS or name == "clear_smtp_password"}
            if isinstance(field, forms.BooleanField):
                output = serializers.BooleanField(**options)
            elif isinstance(field, forms.IntegerField):
                output = serializers.IntegerField(min_value=field.min_value, max_value=field.max_value, **options)
            elif isinstance(field, forms.MultipleChoiceField):
                output = serializers.ListField(child=serializers.ChoiceField(choices=list(field.choices)), **options)
            elif isinstance(field, forms.ChoiceField):
                output = serializers.ChoiceField(choices=list(field.choices), **options)
            elif name == "recipients":
                output = serializers.ListField(child=serializers.EmailField(), **options)
            elif isinstance(field, forms.JSONField):
                output = serializers.JSONField(allow_null=True, **options)
            else:
                output = serializers.CharField(allow_blank=not field.required, trim_whitespace=name != "smtp_password", **options)
            fields[name] = output
        fields["smtp_password_configured"] = serializers.BooleanField(read_only=True)
        fields["webhook_configured"] = serializers.BooleanField(read_only=True)
        return fields

    @staticmethod
    def values(config):
        form = AlertSettingsForm(config=config)
        return {name: form.initial.get(name, field.initial if field.initial is not None else
                                     False if isinstance(field, forms.BooleanField) else
                                     [] if isinstance(field, forms.MultipleChoiceField) or name == "recipients" else
                                     None if isinstance(field, forms.JSONField) else "")
                for name, field in form.fields.items()}

    def to_representation(self, config):
        data = self.values(config)
        for name in SECRET_FIELDS | {"clear_smtp_password"}:
            data.pop(name, None)
        data["smtp_password_configured"] = bool(config and config.email_channel and config.email_channel.smtp_password_encrypted)
        data["webhook_configured"] = bool(config and config.webhook_channel and config.webhook_channel.webhook_url_encrypted)
        return data

    def validate(self, attrs):
        config = self.context.get("config")
        data = {**self.values(config), **attrs}
        self.form = AlertSettingsForm(data, config=config, test_method=self.context.get("test_method"))
        if not self.form.is_valid():
            raise serializers.ValidationError(dict(self.form.errors))
        return attrs

    def save(self, **kwargs):
        try:
            return self.form.save()
        except (SecretConfigurationError, DjangoValidationError) as exc:
            raise ValidationError({"detail": getattr(exc, "messages", [str(exc)])}) from exc


class AlertSettingsAPIView(APIView):
    permission_classes = [IsAuthenticated]
    test_method = None

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if not request.user.is_superuser:
            raise PermissionDenied("Global alert settings require a NetBox superuser.")
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            _require_sensitive_token(request)

    @staticmethod
    def config():
        return AlertSettings.objects.select_related("rule", "email_channel", "webhook_channel").first()

    @extend_schema(responses=AlertSettingsSerializer)
    def get(self, request):
        return Response(AlertSettingsSerializer().to_representation(self.config()))

    @extend_schema(request=AlertSettingsSerializer, responses=AlertSettingsSerializer)
    def patch(self, request):
        serializer = AlertSettingsSerializer(data=request.data, context={"config": self.config()})
        serializer.is_valid(raise_exception=True)
        return Response(serializer.to_representation(serializer.save()))

    @extend_schema(request=AlertSettingsSerializer, responses=AlertSettingsSerializer)
    def put(self, request):
        return self.patch(request)


class AlertSettingsTestAPIView(AlertSettingsAPIView):
    http_method_names = ["post", "options"]

    @extend_schema(request=AlertSettingsSerializer, responses={200: serializers.DictField(), 400: serializers.DictField()})
    def post(self, request):
        serializer = AlertSettingsSerializer(data=request.data, context={"config": self.config(), "test_method": self.test_method})
        serializer.is_valid(raise_exception=True)
        config = serializer.save()
        channel = config.email_channel if self.test_method == "email" else config.webhook_channel
        try:
            sample = send_test_channel(channel)
        except Exception as exc:
            return Response({"detail": f"Settings saved; test {self.test_method} failed ({type(exc).__name__}). Check destination, credentials, and TLS settings."}, status=400)
        return Response({"detail": f"Test {self.test_method} sent successfully.", "sample": sample})
