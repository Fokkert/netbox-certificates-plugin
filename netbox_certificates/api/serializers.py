from django.db import transaction
from rest_framework import serializers
from rest_framework.exceptions import PermissionDenied
from netbox.api.serializers import NetBoxModelSerializer

from netbox_certificates.choices import LinkOriginChoices
from netbox_certificates.models import ArtifactGroup, ArtifactLink, Bundle, Certificate, CertificateAuthority, CSR, ExpiryAlertConfiguration, ExpiryAlertEvent, PrivateKey
from netbox_certificates.permissions import object_allowed
from netbox_certificates.services.duplicates import find_duplicate
from netbox_certificates.services.encryption import encrypt_private_key, encrypt_secret
from netbox_certificates.services.expiry import remaining_days
from netbox_certificates.services.ingest import after_artifact_save
from netbox_certificates.services.parser import ArtifactParseError, parse_blob


def _require_superuser_write_token(request, purpose):
    auth = getattr(request, "auth", None) if request is not None else None
    user = getattr(request, "user", None) if request is not None else None
    if not getattr(user, "is_superuser", False):
        raise PermissionDenied(f"{purpose} requires a NetBox superuser account.")
    if auth is None or not hasattr(auth, "write_enabled"):
        raise PermissionDenied(f"{purpose} requires NetBox API token authentication.")
    if not auth.write_enabled:
        raise PermissionDenied(f"{purpose} requires a write-enabled NetBox API token.")


def _single(parsed, kind):
    matches = [p for p in parsed if p.kind == kind]
    if len(matches) != 1 or len(parsed) != 1:
        raise serializers.ValidationError(f"Expected exactly one {kind.replace('_', ' ')} object.")
    return matches[0]


def _group_details(obj, request=None):
    groups = obj.groups.all().order_by("name")
    user = getattr(request, "user", None) if request is not None else None
    if user is not None and hasattr(ArtifactGroup.objects, "restrict"):
        visible_ids = ArtifactGroup.objects.restrict(user, "view").filter(pk__in=groups.values("pk")).values_list("pk", flat=True)
        groups = groups.filter(pk__in=visible_ids)
    return [{"id": group.pk, "name": group.name, "url": group.get_absolute_url()} for group in groups]


class ArtifactGroupSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:netbox_certificates-api:artifactgroup-detail")
    parent = serializers.PrimaryKeyRelatedField(queryset=ArtifactGroup.objects.all(), required=False, allow_null=True)
    children = serializers.SerializerMethodField()
    members = serializers.SerializerMethodField()
    certificates = serializers.PrimaryKeyRelatedField(many=True, queryset=Certificate.objects.all(), required=False)
    private_keys = serializers.PrimaryKeyRelatedField(many=True, queryset=PrivateKey.objects.all(), required=False)
    csrs = serializers.PrimaryKeyRelatedField(many=True, queryset=CSR.objects.all(), required=False)
    bundles = serializers.PrimaryKeyRelatedField(many=True, queryset=Bundle.objects.all(), required=False)

    class Meta:
        model = ArtifactGroup
        fields = (
            "id", "url", "display", "name", "parent", "children", "members", "owner", "description", "comments",
            "certificates", "private_keys", "csrs", "bundles", "tags", "custom_fields", "created", "last_updated",
        )
        brief_fields = ("id", "url", "display", "name", "parent")

    def validate(self, attrs):
        attrs = super().validate(attrs)
        parent = attrs.get("parent", getattr(self.instance, "parent", None))
        if self.instance is not None and parent is not None:
            if parent.pk == self.instance.pk or parent.pk in set(self.instance.descendant_ids()):
                raise serializers.ValidationError({"parent": "A Group cannot be nested below itself or one of its descendants."})
        request = self.context.get("request")
        if request is not None and parent is not None and not object_allowed(request.user, parent, "view"):
            raise PermissionDenied("Selecting this parent Group requires view permission on it.")
        return attrs

    @staticmethod
    def _memberships(validated_data):
        return {name: validated_data.pop(name, None) for name in ("certificates", "private_keys", "csrs", "bundles")}

    def _validate_members(self, memberships):
        request = self.context.get("request")
        if request is None:
            return
        for objects in memberships.values():
            if objects is None:
                continue
            for obj in objects:
                if not object_allowed(request.user, obj, "change"):
                    raise PermissionDenied(f"Changing Group membership for {obj} requires change permission on that object.")

    @staticmethod
    def _apply_memberships(group, memberships):
        for name, objects in memberships.items():
            if objects is not None:
                getattr(group, name).set(objects)

    @staticmethod
    def _member_item(kind, obj):
        return {"type": kind, "id": obj.pk, "name": str(obj), "url": obj.get_absolute_url()}

    def _visible(self, obj):
        request = self.context.get("request")
        return request is None or object_allowed(request.user, obj, "view")

    def get_children(self, obj):
        return [
            self._member_item("group", item)
            for item in obj.children.all().order_by("name")
            if self._visible(item)
        ]

    def get_members(self, obj):
        result = []
        for kind, queryset in (
            ("group", obj.children.all().order_by("name")),
            ("bundle", obj.bundles.all().order_by("name")),
            ("certificate", obj.certificates.all().order_by("name")),
            ("private_key", obj.private_keys.all().order_by("name")),
            ("csr", obj.csrs.all().order_by("name")),
        ):
            result.extend(self._member_item(kind, item) for item in queryset if self._visible(item))
        return result

    def create(self, validated_data):
        memberships = self._memberships(validated_data)
        self._validate_members(memberships)
        with transaction.atomic():
            group = super().create(validated_data)
            self._apply_memberships(group, memberships)
            return group

    def update(self, instance, validated_data):
        memberships = self._memberships(validated_data)
        self._validate_members(memberships)
        with transaction.atomic():
            group = super().update(instance, validated_data)
            self._apply_memberships(group, memberships)
            return group


class CertificateAuthoritySerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:netbox_certificates-api:certificateauthority-detail")
    certificate_count = serializers.SerializerMethodField()

    class Meta:
        model = CertificateAuthority
        fields = ("id", "url", "display", "name", "certificate_count", "description", "created", "last_updated")
        brief_fields = ("id", "url", "display", "name", "certificate_count")
        read_only_fields = fields

    def get_certificate_count(self, obj):
        request = self.context.get("request")
        if request is None:
            return obj.certificates.count()
        return Certificate.objects.restrict(request.user, "view").filter(authority=obj).count()


class CertificateSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:netbox_certificates-api:certificate-detail")
    material = serializers.CharField(required=False, allow_blank=False)
    remaining_days = serializers.SerializerMethodField()
    authority = serializers.PrimaryKeyRelatedField(read_only=True)
    authority_details = serializers.SerializerMethodField()
    groups = serializers.PrimaryKeyRelatedField(many=True, queryset=ArtifactGroup.objects.all(), required=False)
    group_details = serializers.SerializerMethodField()

    class Meta:
        model = Certificate
        fields = (
            "id", "url", "display", "name", "status", "source_filename", "source_format", "material",
            "fingerprint_sha256", "public_key_fingerprint", "serial_number", "subject", "issuer", "authority", "authority_details",
            "subject_alternative_names", "valid_from", "valid_to", "signature_algorithm", "key_type",
            "key_size", "curve", "is_ca", "parent_certificate", "supersedes", "remaining_days",
            "alert_trigger", "trigger_unit", "owner", "groups", "group_details", "description", "comments",
            "tags", "custom_fields", "created", "last_updated",
        )
        brief_fields = ("id", "url", "display", "name", "status", "valid_to", "remaining_days", "groups")
        read_only_fields = (
            "status", "source_format", "fingerprint_sha256", "public_key_fingerprint", "serial_number", "subject",
            "issuer", "authority", "authority_details", "subject_alternative_names", "valid_from", "valid_to", "signature_algorithm", "key_type",
            "key_size", "curve", "is_ca", "parent_certificate", "remaining_days", "group_details",
        )
    def get_remaining_days(self, obj): return remaining_days(obj)
    def get_authority_details(self, obj):
        if obj.authority is None:
            return None
        return {"id": obj.authority.pk, "name": obj.authority.name, "url": obj.authority.get_absolute_url()}
    def get_group_details(self, obj): return _group_details(obj, self.context.get("request"))
    def validate(self, attrs):
        material = attrs.pop("material", None)
        if self.instance is None and not material:
            raise serializers.ValidationError({"material": "Certificate material is required."})
        if material:
            try: parsed = _single(parse_blob(material.encode(), filename=attrs.get("source_filename") or "certificate.pem"), "certificate")
            except ArtifactParseError as exc: raise serializers.ValidationError({"material": str(exc)}) from exc
            duplicate = find_duplicate("certificate", parsed.metadata, exclude_pk=self.instance.pk if self.instance else None)
            if duplicate: raise serializers.ValidationError({"material": duplicate.message()})
            self._parsed = parsed
            attrs = self._prepare(attrs)
        return super().validate(attrs)
    def _prepare(self, data):
        parsed = getattr(self, "_parsed", None)
        if parsed:
            data["material"] = parsed.data.decode("ascii"); data.update(parsed.metadata); data["source_format"] = parsed.source_format; data.setdefault("name", parsed.name)
        return data
    def create(self, validated_data):
        with transaction.atomic():
            obj = super().create(self._prepare(validated_data)); after_artifact_save(obj); return obj
    def update(self, instance, validated_data):
        with transaction.atomic():
            obj = super().update(instance, self._prepare(validated_data)); after_artifact_save(obj); return obj


class PrivateKeySerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:netbox_certificates-api:privatekey-detail")
    key_material = serializers.CharField(write_only=True, required=False, allow_blank=False)
    input_password = serializers.CharField(write_only=True, required=False, allow_blank=True)
    groups = serializers.PrimaryKeyRelatedField(many=True, queryset=ArtifactGroup.objects.all(), required=False)
    group_details = serializers.SerializerMethodField()
    class Meta:
        model = PrivateKey
        fields = ("id", "url", "display", "name", "source_filename", "source_format", "key_material", "input_password", "material_sha256", "public_key_fingerprint", "key_type", "key_size", "encrypted_on_import", "owner", "groups", "group_details", "description", "comments", "tags", "custom_fields", "created", "last_updated")
        brief_fields = ("id", "url", "display", "name", "key_type", "public_key_fingerprint", "groups")
        read_only_fields = ("source_format", "material_sha256", "public_key_fingerprint", "key_type", "key_size", "encrypted_on_import", "group_details")
    def get_group_details(self, obj): return _group_details(obj, self.context.get("request"))
    def validate(self, attrs):
        material = attrs.pop("key_material", None); password = attrs.pop("input_password", None) or None; attrs = super().validate(attrs)
        if self.instance is None and not material: raise serializers.ValidationError({"key_material": "Private key material is required."})
        if material:
            _require_superuser_write_token(self.context.get("request"), "Private-key material API access")
            try: parsed = _single(parse_blob(material.encode(), password=password, filename=attrs.get("source_filename") or "private.key"), "private_key")
            except ArtifactParseError as exc: raise serializers.ValidationError({"key_material": str(exc)}) from exc
            duplicate = find_duplicate("private_key", parsed.metadata, exclude_pk=self.instance.pk if self.instance else None)
            if duplicate: raise serializers.ValidationError({"key_material": duplicate.message()})
            self._parsed = parsed
        return attrs
    def _prepare(self, data):
        parsed = getattr(self, "_parsed", None)
        if parsed:
            data["encrypted_material"] = encrypt_private_key(parsed.data); metadata = parsed.metadata.copy(); metadata.pop("curve", None); data.update(metadata); data["source_format"] = parsed.source_format; data.setdefault("name", parsed.name)
        return data
    def create(self, validated_data):
        with transaction.atomic(): obj = super().create(self._prepare(validated_data)); after_artifact_save(obj); return obj
    def update(self, instance, validated_data):
        with transaction.atomic(): obj = super().update(instance, self._prepare(validated_data)); after_artifact_save(obj); return obj


class CSRSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:netbox_certificates-api:csr-detail")
    material = serializers.CharField(required=False, allow_blank=False)
    groups = serializers.PrimaryKeyRelatedField(many=True, queryset=ArtifactGroup.objects.all(), required=False)
    group_details = serializers.SerializerMethodField()
    class Meta:
        model = CSR
        fields = ("id", "url", "display", "name", "source_filename", "source_format", "material", "fingerprint_sha256", "public_key_fingerprint", "subject", "subject_alternative_names", "signature_algorithm", "key_type", "key_size", "curve", "owner", "groups", "group_details", "description", "comments", "tags", "custom_fields", "created", "last_updated")
        brief_fields = ("id", "url", "display", "name", "subject", "public_key_fingerprint", "groups")
        read_only_fields = ("source_format", "fingerprint_sha256", "public_key_fingerprint", "subject", "subject_alternative_names", "signature_algorithm", "key_type", "key_size", "curve", "group_details")
    def get_group_details(self, obj): return _group_details(obj, self.context.get("request"))
    def validate(self, attrs):
        material = attrs.pop("material", None)
        if self.instance is None and not material: raise serializers.ValidationError({"material": "CSR material is required."})
        if material:
            try: parsed = _single(parse_blob(material.encode(), filename=attrs.get("source_filename") or "request.csr"), "csr")
            except ArtifactParseError as exc: raise serializers.ValidationError({"material": str(exc)}) from exc
            duplicate = find_duplicate("csr", parsed.metadata, exclude_pk=self.instance.pk if self.instance else None)
            if duplicate: raise serializers.ValidationError({"material": duplicate.message()})
            self._parsed = parsed
            attrs = self._prepare(attrs)
        return super().validate(attrs)
    def _prepare(self, data):
        parsed = getattr(self, "_parsed", None)
        if parsed: data["material"] = parsed.data.decode("ascii"); data.update(parsed.metadata); data["source_format"] = parsed.source_format; data.setdefault("name", parsed.name)
        return data
    def create(self, validated_data):
        with transaction.atomic(): obj = super().create(self._prepare(validated_data)); after_artifact_save(obj); return obj
    def update(self, instance, validated_data):
        with transaction.atomic(): obj = super().update(instance, self._prepare(validated_data)); after_artifact_save(obj); return obj


class BundleSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:netbox_certificates-api:bundle-detail")
    certificate = serializers.SerializerMethodField(); private_key = serializers.SerializerMethodField(); csr = serializers.SerializerMethodField(); chain_certificates = serializers.SerializerMethodField()
    groups = serializers.PrimaryKeyRelatedField(many=True, queryset=ArtifactGroup.objects.all(), required=False)
    group_details = serializers.SerializerMethodField()
    class Meta:
        model = Bundle
        fields = ("id", "url", "display", "name", "identity_fingerprint", "source_filename", "archive_format", "status", "certificate", "private_key", "csr", "chain_certificates", "owner", "groups", "group_details", "description", "comments", "tags", "custom_fields", "created", "last_updated")
        brief_fields = ("id", "url", "display", "name", "status", "groups")
        read_only_fields = ("name", "identity_fingerprint", "source_filename", "archive_format", "status", "certificate", "private_key", "csr", "chain_certificates", "group_details")
    def _visible(self, obj):
        if obj is None: return None
        request = self.context.get("request")
        if request is None: return obj
        return obj if obj.__class__.objects.restrict(request.user, "view").filter(pk=obj.pk).exists() else None
    def get_certificate(self, obj):
        value = self._visible(obj.certificate); return CertificateSerializer(value, context=self.context).data if value else None
    def get_private_key(self, obj):
        value = self._visible(obj.private_key); return PrivateKeySerializer(value, context=self.context).data if value else None
    def get_csr(self, obj):
        value = self._visible(obj.csr); return CSRSerializer(value, context=self.context).data if value else None
    def get_chain_certificates(self, obj):
        request = self.context.get("request"); qs = obj.chain_certificates.all(); qs = qs.restrict(request.user, "view") if request is not None else qs
        return CertificateSerializer(qs, many=True, context=self.context).data
    def get_group_details(self, obj): return _group_details(obj, self.context.get("request"))


class ArtifactLinkSerializer(NetBoxModelSerializer):
    display = serializers.SerializerMethodField()
    class Meta:
        model = ArtifactLink
        fields = ("id", "display", "source_type", "source_id", "target_type", "target_id", "relation", "origin", "active", "note", "created", "last_updated")
        read_only_fields = ("origin", "created", "last_updated")
    def get_display(self, obj): return f"Artifact link #{obj.pk}"
    def _resolve_visible_endpoint(self, object_type, object_id, field):
        model = object_type.model_class() if object_type else None; manager = getattr(model, "objects", None) if model else None; request = self.context.get("request")
        if model is None or manager is None: raise serializers.ValidationError({field: "The selected object type cannot be linked."})
        qs = manager.all(); qs = qs.restrict(request.user, "view") if request is not None and hasattr(qs, "restrict") else qs
        try: return qs.get(pk=object_id)
        except model.DoesNotExist: raise serializers.ValidationError({field: "The selected object does not exist or is not visible."})
    def validate(self, attrs):
        attrs = super().validate(attrs)
        source_type = attrs.get("source_type", getattr(self.instance, "source_type", None)); source_id = attrs.get("source_id", getattr(self.instance, "source_id", None)); target_type = attrs.get("target_type", getattr(self.instance, "target_type", None)); target_id = attrs.get("target_id", getattr(self.instance, "target_id", None))
        source = self._resolve_visible_endpoint(source_type, source_id, "source_id"); target = self._resolve_visible_endpoint(target_type, target_id, "target_id")
        if not isinstance(source, (Certificate, PrivateKey, CSR, Bundle)) and not isinstance(target, (Certificate, PrivateKey, CSR, Bundle)):
            raise serializers.ValidationError("At least one endpoint must be a NetBox Certificates object.")
        if source_type.pk == target_type.pk and source_id == target_id: raise serializers.ValidationError("An object cannot be linked to itself.")
        return attrs
    def create(self, validated_data): validated_data["origin"] = LinkOriginChoices.MANUAL; return super().create(validated_data)
    def update(self, instance, validated_data):
        if instance.origin != LinkOriginChoices.MANUAL: raise serializers.ValidationError("Automatically generated links cannot be modified through the API.")
        validated_data["origin"] = LinkOriginChoices.MANUAL; return super().update(instance, validated_data)


class ExpiryAlertConfigurationSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:netbox_certificates-api:expiration-alert-configuration-detail")
    smtp_password = serializers.CharField(write_only=True, required=False, allow_blank=True, trim_whitespace=False)
    webhook_url = serializers.URLField(write_only=True, required=False, allow_blank=True)
    webhook_bearer_token = serializers.CharField(write_only=True, required=False, allow_blank=True, trim_whitespace=False)
    smtp_password_configured = serializers.SerializerMethodField(); webhook_url_configured = serializers.SerializerMethodField(); webhook_bearer_token_configured = serializers.SerializerMethodField()
    class Meta:
        model = ExpiryAlertConfiguration
        fields = (
            "id", "url", "display", "check_interval_minutes", "alert_on_expired_certificates", "alert_repeat_mode",
            "email_enabled", "smtp_host", "smtp_port", "smtp_username", "smtp_password", "smtp_password_configured", "smtp_use_tls", "smtp_use_ssl", "email_from_address", "email_recipients", "include_superusers",
            "webhook_enabled", "webhook_url", "webhook_url_configured", "webhook_bearer_token", "webhook_bearer_token_configured", "webhook_allow_http", "webhook_ignore_tls_verification",
            "last_check_at", "last_check_success", "last_check_message", "email_last_test_at", "email_last_test_success", "email_last_test_message", "webhook_last_test_at", "webhook_last_test_success", "webhook_last_test_message", "custom_fields", "created", "last_updated",
        )
        brief_fields = ("id", "url", "display", "alert_on_expired_certificates", "alert_repeat_mode", "email_enabled", "webhook_enabled", "last_check_at", "last_check_success")
        read_only_fields = ("last_check_at", "last_check_success", "last_check_message", "email_last_test_at", "email_last_test_success", "email_last_test_message", "webhook_last_test_at", "webhook_last_test_success", "webhook_last_test_message")
    def get_smtp_password_configured(self, obj): return bool(obj.smtp_password_encrypted)
    def get_webhook_url_configured(self, obj): return bool(obj.webhook_url_encrypted)
    def get_webhook_bearer_token_configured(self, obj): return bool(obj.webhook_bearer_token_encrypted)
    def validate(self, attrs):
        smtp_password = attrs.pop("smtp_password", None); webhook_url = attrs.pop("webhook_url", None); webhook_token = attrs.pop("webhook_bearer_token", None)
        if smtp_password or webhook_token: _require_superuser_write_token(self.context.get("request"), "Alert secret API access")
        attrs = super().validate(attrs)
        tls = attrs.get("smtp_use_tls", getattr(self.instance, "smtp_use_tls", True)); ssl = attrs.get("smtp_use_ssl", getattr(self.instance, "smtp_use_ssl", False))
        if tls and ssl: raise serializers.ValidationError({"smtp_use_ssl": "TLS and implicit SSL cannot both be enabled."})
        email_enabled = attrs.get("email_enabled", getattr(self.instance, "email_enabled", False))
        if email_enabled:
            host = attrs.get("smtp_host", getattr(self.instance, "smtp_host", "")); port = attrs.get("smtp_port", getattr(self.instance, "smtp_port", None)); sender = attrs.get("email_from_address", getattr(self.instance, "email_from_address", "")); include_superusers = attrs.get("include_superusers", getattr(self.instance, "include_superusers", True)); recipients = attrs.get("email_recipients", getattr(self.instance, "email_recipients", "")); errors = {}
            if not host: errors["smtp_host"] = "SMTP host is required when email alerts are enabled."
            if not port: errors["smtp_port"] = "SMTP port is required when email alerts are enabled."
            if not sender: errors["email_from_address"] = "From address is required when email alerts are enabled."
            if not include_superusers and not str(recipients).strip(): errors["email_recipients"] = "Configure a recipient or enable NetBox superuser recipients."
            if errors: raise serializers.ValidationError(errors)
        webhook_enabled = attrs.get("webhook_enabled", getattr(self.instance, "webhook_enabled", False)); existing_webhook = bool(getattr(self.instance, "webhook_url_encrypted", None)); allow_http = attrs.get("webhook_allow_http", getattr(self.instance, "webhook_allow_http", False))
        if webhook_enabled and not webhook_url and not existing_webhook: raise serializers.ValidationError({"webhook_url": "Webhook URL is required when webhook alerts are enabled."})
        if webhook_url and webhook_url.lower().startswith("http://") and not allow_http: raise serializers.ValidationError({"webhook_url": "HTTP webhooks require webhook_allow_http=true."})
        self._smtp_password, self._webhook_url, self._webhook_token = smtp_password, webhook_url, webhook_token
        return attrs
    def _apply_secrets(self, data):
        if getattr(self, "_smtp_password", None): data["smtp_password_encrypted"] = encrypt_secret(self._smtp_password)
        if getattr(self, "_webhook_url", None): data["webhook_url_encrypted"] = encrypt_secret(self._webhook_url)
        if getattr(self, "_webhook_token", None): data["webhook_bearer_token_encrypted"] = encrypt_secret(self._webhook_token)
        return data
    def create(self, validated_data):
        if ExpiryAlertConfiguration.objects.exists(): raise serializers.ValidationError("Only one expiration alert configuration can exist.")
        return super().create(self._apply_secrets(validated_data))
    def update(self, instance, validated_data): return super().update(instance, self._apply_secrets(validated_data))


class ExpiryAlertEventSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:netbox_certificates-api:expiration-alert-event-detail")
    class Meta:
        model = ExpiryAlertEvent
        fields = ("id", "url", "display", "certificate", "method", "certificate_valid_to", "trigger_unit", "alert_trigger", "trigger_at", "last_attempt_at", "delivered_at", "success", "attempt_count", "status_code", "message", "custom_fields", "created", "last_updated")
        brief_fields = ("id", "url", "display", "certificate", "method", "success", "last_attempt_at", "attempt_count")
        read_only_fields = fields
