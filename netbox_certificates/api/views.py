import io
import tarfile
import zipfile

from django.http import HttpResponse
from django.db.models import F
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.exceptions import APIException, MethodNotAllowed, PermissionDenied, ValidationError
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from netbox.api.viewsets import NetBoxModelViewSet
from users.models import Owner

from netbox_certificates.constants import MAX_UPLOAD_BYTES
from netbox_certificates.filtersets import ArtifactGroupFilterSet, BundleFilterSet, CertificateAuthorityFilterSet, CertificateFilterSet, CSRFilterSet, PrivateKeyFilterSet
from netbox_certificates.models import ArtifactGroup, ArtifactLink, Bundle, Certificate, CertificateAuthority, CSR, ExpiryAlertConfiguration, ExpiryAlertEvent, PrivateKey
from netbox_certificates.permissions import action_queryset, object_allowed
from netbox_certificates.services.alerts import ExpiryAlertError, run_expiry_alert_scan, send_email, send_webhook
from netbox_certificates.services.bundles import BundleImportError, BundleImportPermissionError, import_bundle
from netbox_certificates.services.chain import ordered_chain
from netbox_certificates.services.csr import CSRGenerationError, generate_csr
from netbox_certificates.services.encryption import PrivateKeyEncryptionError, decrypt_private_key, encrypt_private_key
from netbox_certificates.services.expiry import expiry_state
from netbox_certificates.services.importing import _check_created_permission
from netbox_certificates.services.ingest import after_artifact_save
from netbox_certificates.services.inventory import build_inventory
from netbox_certificates.services.parser import ArtifactParseError, parse_blob
from netbox_certificates.services.pkcs12_export import PFXExportError, build_pfx
from netbox_certificates.services.unified_import import UnifiedImportError, UploadItem, import_objects

from .serializers import ArtifactGroupSerializer, ArtifactLinkSerializer, BundleSerializer, CertificateAuthoritySerializer, CertificateSerializer, CSRSerializer, ExpiryAlertConfigurationSerializer, ExpiryAlertEventSerializer, PrivateKeySerializer


def _require_sensitive_token(request):
    auth = getattr(request, "auth", None)
    if auth is None or not hasattr(auth, "write_enabled"):
        raise PermissionDenied("This operation requires NetBox API token authentication.")
    if not auth.write_enabled:
        raise PermissionDenied("This operation requires a write-enabled NetBox API token.")


def _require_superuser_token(request):
    _require_sensitive_token(request)
    if not getattr(request.user, "is_superuser", False):
        raise PermissionDenied("Private-key material API access is restricted to NetBox superusers.")


def _artifact_token(obj):
    model_name = obj._meta.model_name
    value = obj.fingerprint_sha256 if model_name in {"certificate", "csr"} else obj.public_key_fingerprint if model_name == "privatekey" else getattr(obj, "identity_fingerprint", "") or ""
    value = "".join(ch for ch in str(value).lower() if ch.isalnum())
    return value[:12] or f"{obj.pk:012x}"


def _artifact_filename(obj, extension):
    prefix = {"certificate": "certificate", "privatekey": "private-key", "csr": "csr"}.get(obj._meta.model_name, obj._meta.model_name.replace("_", "-"))
    return f"{prefix}-{_artifact_token(obj)}{extension}"


def _bundle_filename(obj, extension): return f"bundle-{_artifact_token(obj)}{extension}"


def _secure_response(data, filename, content_type):
    response = HttpResponse(data, content_type=content_type)
    response["Content-Disposition"] = f'attachment; filename="{filename}"'
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"; response["Pragma"] = "no-cache"; response["X-Content-Type-Options"] = "nosniff"
    return response


def _archive(files, fmt):
    output = io.BytesIO()
    if fmt == "zip":
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, data in files:
                info = zipfile.ZipInfo(name); info.external_attr = 0o600 << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
        return output.getvalue(), "application/zip", ".zip"
    if fmt == "tar":
        with tarfile.open(fileobj=output, mode="w") as archive:
            for name, data in files:
                info = tarfile.TarInfo(name); info.size, info.mode, info.mtime = len(data), 0o600, 0
                archive.addfile(info, io.BytesIO(data))
        return output.getvalue(), "application/x-tar", ".tar"
    raise PermissionDenied("Unsupported archive format. Use zip or tar.")


def _bool_value(value, default=False):
    if value is None: return default
    if isinstance(value, bool): return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _list_value(value):
    if value is None: return []
    if isinstance(value, (list, tuple)): return list(value)
    if isinstance(value, str): return [part.strip() for part in value.replace("\n", ",").split(",") if part.strip()]
    return [value]


def _group_queryset(request, values):
    ids = []
    for value in values:
        try: ids.append(int(value))
        except (TypeError, ValueError): raise APIException(f"Invalid group ID: {value!r}")
    qs = ArtifactGroup.objects.restrict(request.user, "view").filter(pk__in=ids)
    if len(set(ids)) != qs.count(): raise PermissionDenied("One or more requested Groups do not exist or are not visible.")
    return list(qs)


class CertificateViewSet(NetBoxModelViewSet):
    queryset = Certificate.objects.select_related("authority", "parent_certificate", "supersedes", "owner").prefetch_related("tags", "groups")
    serializer_class = CertificateSerializer
    filterset_class = CertificateFilterSet
    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated])
    def download(self, request, pk=None):
        _require_sensitive_token(request)
        try: obj = action_queryset(Certificate, request.user, "download").get(pk=pk)
        except Certificate.DoesNotExist: raise PermissionDenied("Certificate download permission denied.")
        return _secure_response(obj.material.encode("ascii"), _artifact_filename(obj, ".crt"), "application/x-pem-file")
    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated], url_path="expiration-summary")
    def expiration_summary(self, request):
        qs = action_queryset(Certificate, request.user, "view").order_by("valid_to")
        states = [(cert, expiry_state(cert)) for cert in qs]
        counts = {key: sum(1 for _, state in states if state["level"] == key) for key in ("healthy", "warning", "critical", "expired", "unknown")}
        upcoming = [{"certificate": CertificateSerializer(cert, context={"request": request}).data, "expiry": state} for cert, state in states if state["level"] in {"warning", "critical"}][:50]
        return Response({"counts": counts, "upcoming": upcoming})
    @action(detail=False, methods=["get"], permission_classes=[IsAuthenticated], url_path="inventory")
    def inventory(self, request): return Response(build_inventory(request.user))


class CertificateAuthorityViewSet(NetBoxModelViewSet):
    queryset = CertificateAuthority.objects.filter(
        certificates__is_ca=True,
        certificates__parent_certificate__isnull=True,
        certificates__subject=F("certificates__issuer"),
    ).prefetch_related("certificates").distinct()
    serializer_class = CertificateAuthoritySerializer
    filterset_class = CertificateAuthorityFilterSet
    http_method_names = ["get", "head", "options"]


class PrivateKeyViewSet(NetBoxModelViewSet):
    queryset = PrivateKey.objects.select_related("owner").prefetch_related("tags", "groups")
    serializer_class = PrivateKeySerializer; filterset_class = PrivateKeyFilterSet
    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated])
    def download(self, request, pk=None):
        _require_superuser_token(request)
        try: obj = action_queryset(PrivateKey, request.user, "download").get(pk=pk)
        except PrivateKey.DoesNotExist: raise PermissionDenied("Private-key download permission denied.")
        try: data = decrypt_private_key(obj.encrypted_material)
        except PrivateKeyEncryptionError as exc: raise APIException("Stored private key could not be decrypted.") from exc
        return _secure_response(data, _artifact_filename(obj, ".key"), "application/x-pem-file")


class CSRViewSet(NetBoxModelViewSet):
    queryset = CSR.objects.select_related("owner").prefetch_related("tags", "groups")
    serializer_class = CSRSerializer; filterset_class = CSRFilterSet
    @action(detail=True, methods=["get"], permission_classes=[IsAuthenticated])
    def download(self, request, pk=None):
        _require_sensitive_token(request)
        try: obj = action_queryset(CSR, request.user, "download").get(pk=pk)
        except CSR.DoesNotExist: raise PermissionDenied("CSR download permission denied.")
        return _secure_response(obj.material.encode("ascii"), _artifact_filename(obj, ".csr"), "application/pkcs10")
    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated])
    def generate(self, request):
        _require_superuser_token(request)
        data = request.data; common_name = str(data.get("common_name", "")).strip()
        if not common_name: raise APIException("common_name is required.")
        raw_sans = data.get("sans", []); raw_sans = raw_sans if isinstance(raw_sans, (list, tuple)) else _list_value(raw_sans)
        sans = []
        for item in raw_sans or []:
            if isinstance(item, dict):
                kind, value = str(item.get("type", "DNS")).upper().strip(), str(item.get("value", "")).strip()
                if value: sans.append(f"{kind}:{value}")
            elif str(item).strip(): sans.append(str(item).strip())
        try:
            key_pem, csr_pem = generate_csr(common_name=common_name, sans=sans, key_algorithm=str(data.get("key_algorithm", "rsa")), rsa_bits=int(data.get("rsa_bits", 3072)), ec_curve=str(data.get("ec_curve", "secp256r1")), signature_hash=str(data.get("signature_hash", "sha256")), rsa_signature=str(data.get("rsa_signature", "pkcs1v15")), country=str(data.get("country", "")), state=str(data.get("state", "")), locality=str(data.get("locality", "")), organization=str(data.get("organization", "")), organizational_unit=str(data.get("organizational_unit", "")), street_address=str(data.get("street_address", "")), postal_code=str(data.get("postal_code", "")), subject_serial_number=str(data.get("subject_serial_number", "")), email=str(data.get("email", "")), key_usages=_list_value(data.get("key_usages")), extended_key_usages=_list_value(data.get("extended_key_usages")), request_ca=_bool_value(data.get("request_ca")), path_length=data.get("path_length"))
            key_p = next(p for p in parse_blob(key_pem, filename="generated.key") if p.kind == "private_key"); csr_p = next(p for p in parse_blob(csr_pem, filename="generated.csr") if p.kind == "csr")
        except (CSRGenerationError, ArtifactParseError, StopIteration, TypeError, ValueError) as exc: raise APIException(str(exc)) from exc
        groups = _group_queryset(request, _list_value(data.get("groups"))) if data.get("groups") is not None else []
        from django.db import transaction
        with transaction.atomic():
            key_meta = {k: v for k, v in key_p.metadata.items() if k != "curve"}
            key = PrivateKey.objects.create(name=str(data.get("name") or common_name) + " key", source_filename="generated.key", source_format="pem", encrypted_material=encrypt_private_key(key_p.data), **key_meta); _check_created_permission(request.user, key)
            csr = CSR.objects.create(name=str(data.get("name") or common_name), source_filename="generated.csr", source_format="pem", material=csr_p.data.decode("ascii"), **csr_p.metadata); _check_created_permission(request.user, csr)
            if groups: key.groups.add(*groups); csr.groups.add(*groups)
            after_artifact_save(key); after_artifact_save(csr)
        return Response({"csr": CSRSerializer(csr, context={"request": request}).data, "private_key": PrivateKeySerializer(key, context={"request": request}).data}, status=status.HTTP_201_CREATED)


class BundleViewSet(NetBoxModelViewSet):
    queryset = Bundle.objects.select_related("certificate", "private_key", "csr", "owner").prefetch_related("chain_certificates", "tags", "groups")
    serializer_class = BundleSerializer; filterset_class = BundleFilterSet
    def create(self, request, *args, **kwargs): raise MethodNotAllowed("POST", detail="Use /import-objects/ to create a Bundle from cryptographic material.")
    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def export(self, request, pk=None):
        _require_sensitive_token(request); pfx = _bool_value(request.data.get("pfx"), False); action_name = "export_pfx" if pfx else "export"
        try: bundle = action_queryset(Bundle, request.user, action_name).select_related("certificate", "private_key", "csr").prefetch_related("chain_certificates").get(pk=pk)
        except Bundle.DoesNotExist: raise PermissionDenied("Bundle export permission denied.")
        if pfx or bundle.private_key is not None: _require_superuser_token(request)
        if sum(member is not None for member in (bundle.certificate, bundle.private_key, bundle.csr)) < 2: raise APIException("A Bundle must contain at least two matching primary objects before export.")
        fmt, include_chain = str(request.data.get("format", "zip")).lower(), _bool_value(request.data.get("include_chain"), False)
        if pfx:
            if bundle.certificate is None or bundle.private_key is None: raise APIException("PFX export requires a certificate and matching private key.")
            chain = []
            if include_chain:
                chain = ordered_chain(bundle.certificate); chain.extend(c for c in bundle.chain_certificates.all() if c.pk not in {x.pk for x in chain})
            try: pfx_data = build_pfx(bundle, str(request.data.get("password", "")), chain_certificates=chain)
            except PFXExportError as exc: raise APIException(str(exc)) from exc
            files = [(_artifact_filename(bundle.certificate, ".pfx"), pfx_data)]
            if bundle.csr: files.append((_artifact_filename(bundle.csr, ".csr"), bundle.csr.material.encode("ascii")))
        else:
            files = []
            if bundle.certificate: files.append((_artifact_filename(bundle.certificate, ".crt"), bundle.certificate.material.encode("ascii")))
            if bundle.private_key:
                try: key_data = decrypt_private_key(bundle.private_key.encrypted_material)
                except PrivateKeyEncryptionError as exc: raise APIException("Stored private key could not be decrypted.") from exc
                files.append((_artifact_filename(bundle.private_key, ".key"), key_data))
            if bundle.csr: files.append((_artifact_filename(bundle.csr, ".csr"), bundle.csr.material.encode("ascii")))
            if include_chain:
                chain = ordered_chain(bundle.certificate) if bundle.certificate else []; seen = {c.pk for c in chain}; chain.extend(c for c in bundle.chain_certificates.all() if c.pk not in seen); names = {n for n, _ in files}
                for cert in chain:
                    filename = _artifact_filename(cert, ".crt")
                    if filename not in names: files.append((filename, cert.material.encode("ascii"))); names.add(filename)
        data, content_type, ext = _archive(files, fmt)
        return _secure_response(data, _bundle_filename(bundle, ext), content_type)


class ArtifactGroupViewSet(NetBoxModelViewSet):
    queryset = ArtifactGroup.objects.select_related("owner", "parent").prefetch_related(
        "children", "certificates", "private_keys", "csrs", "bundles", "tags"
    )
    serializer_class = ArtifactGroupSerializer
    filterset_class = ArtifactGroupFilterSet


class ExpiryAlertConfigurationViewSet(NetBoxModelViewSet):
    queryset = ExpiryAlertConfiguration.objects.order_by("pk")
    serializer_class = ExpiryAlertConfigurationSerializer
    def destroy(self, request, *args, **kwargs): raise MethodNotAllowed("DELETE", detail="Expiration alert configuration is a singleton; disable its methods instead.")
    @action(detail=False, methods=["post"], permission_classes=[IsAuthenticated], url_path="run-scan")
    def run_scan(self, request):
        _require_sensitive_token(request)
        if not getattr(request.user, "is_superuser", False) and not request.user.has_perm("netbox_certificates.change_expiryalertconfiguration"): raise PermissionDenied("Running the expiration-alert scan requires expiration-alert configuration permission.")
        return Response(run_expiry_alert_scan(force=_bool_value(request.data.get("force"), False)))
    def _test_allowed(self, request, obj): return getattr(request.user, "is_superuser", False) or object_allowed(request.user, obj, "test") or object_allowed(request.user, obj, "change")
    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def test_email(self, request, pk=None):
        _require_sensitive_token(request); obj = self.get_object()
        if not self._test_allowed(request, obj): raise PermissionDenied("Expiration alert test permission denied.")
        now = timezone.now()
        try:
            result = send_email(obj, test=True); obj.email_last_test_at = now; obj.email_last_test_success = True; obj.email_last_test_message = result[:500]; obj.save(update_fields=("email_last_test_at", "email_last_test_success", "email_last_test_message", "last_updated")); return Response({"success": True, "message": result})
        except Exception as exc:
            message = str(exc) if isinstance(exc, ExpiryAlertError) else f"Email test failed: {exc}"; obj.email_last_test_at = now; obj.email_last_test_success = False; obj.email_last_test_message = message[:500]; obj.save(update_fields=("email_last_test_at", "email_last_test_success", "email_last_test_message", "last_updated")); raise APIException(message) from exc
    @action(detail=True, methods=["post"], permission_classes=[IsAuthenticated])
    def test_webhook(self, request, pk=None):
        _require_sensitive_token(request); obj = self.get_object()
        if not self._test_allowed(request, obj): raise PermissionDenied("Expiration alert test permission denied.")
        now = timezone.now()
        try:
            code, result = send_webhook(obj, test=True); obj.webhook_last_test_at = now; obj.webhook_last_test_success = True; obj.webhook_last_test_message = result[:500]; obj.save(update_fields=("webhook_last_test_at", "webhook_last_test_success", "webhook_last_test_message", "last_updated")); return Response({"success": True, "status_code": code, "message": result})
        except Exception as exc:
            message = str(exc) if isinstance(exc, ExpiryAlertError) else f"Webhook test failed: {exc}"; obj.webhook_last_test_at = now; obj.webhook_last_test_success = False; obj.webhook_last_test_message = message[:500]; obj.save(update_fields=("webhook_last_test_at", "webhook_last_test_success", "webhook_last_test_message", "last_updated")); raise APIException(message) from exc


class ExpiryAlertEventViewSet(NetBoxModelViewSet):
    queryset = ExpiryAlertEvent.objects.select_related("certificate"); serializer_class = ExpiryAlertEventSerializer
    def create(self, request, *args, **kwargs): raise MethodNotAllowed("POST", detail="Expiration alert events are generated by the worker.")
    def update(self, request, *args, **kwargs): raise MethodNotAllowed("PUT", detail="Expiration alert events are read-only records.")
    def partial_update(self, request, *args, **kwargs): raise MethodNotAllowed("PATCH", detail="Expiration alert events are read-only records.")


class ArtifactLinkViewSet(NetBoxModelViewSet):
    queryset = ArtifactLink.objects.select_related("source_type", "target_type"); serializer_class = ArtifactLinkSerializer
    def get_queryset(self):
        qs = super().get_queryset(); visible_ids = []
        for link in qs:
            if all(obj is None or object_allowed(self.request.user, obj, "view") for obj in (link.source_object, link.target_object)): visible_ids.append(link.pk)
        return qs.filter(pk__in=visible_ids)
    def update(self, request, *args, **kwargs):
        if self.get_object().origin != "manual": raise PermissionDenied("Automatically generated links cannot be modified through the API.")
        return super().update(request, *args, **kwargs)
    def partial_update(self, request, *args, **kwargs):
        if self.get_object().origin != "manual": raise PermissionDenied("Automatically generated links cannot be modified through the API.")
        return super().partial_update(request, *args, **kwargs)
    def destroy(self, request, *args, **kwargs):
        if self.get_object().origin != "manual": raise PermissionDenied("Automatically generated links cannot be deleted through the API.")
        return super().destroy(request, *args, **kwargs)


class UnifiedImportAPIView(APIView):
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser]
    def post(self, request):
        _require_sensitive_token(request)
        uploads = request.FILES.getlist("files")
        if not uploads:
            raise ValidationError({"files": ["Multipart field 'files' is required."]})
        total = sum(upload.size for upload in uploads)
        if total > MAX_UPLOAD_BYTES:
            raise ValidationError({"files": [f"Combined upload is too large ({total} bytes); limit is {MAX_UPLOAD_BYTES} bytes."]})
        allowed_kinds = {kind for kind, permission in {"certificate": "netbox_certificates.add_certificate", "csr": "netbox_certificates.add_csr"}.items() if request.user.has_perm(permission)}
        auth = getattr(request, "auth", None)
        if getattr(request.user, "is_superuser", False) and auth is not None and getattr(auth, "write_enabled", False) and request.user.has_perm("netbox_certificates.add_privatekey"): allowed_kinds.add("private_key")
        groups_raw = request.data.getlist("groups") if hasattr(request.data, "getlist") else _list_value(request.data.get("groups"))
        if not groups_raw and request.data.get("groups"): groups_raw = _list_value(request.data.get("groups"))
        groups = _group_queryset(request, groups_raw) if groups_raw else []
        owner = Owner.objects.filter(pk=request.data.get("owner")).first() if request.data.get("owner") else None
        items = [UploadItem(upload.name, upload.read()) for upload in uploads]
        try:
            result = import_objects(uploads=items, allowed_kinds=allowed_kinds, user=request.user, owner=owner, groups=groups, password=request.data.get("password") or None, archive_password=request.data.get("archive_password") or None, import_chain=_bool_value(request.data.get("import_chain"), True), preserve_archive=_bool_value(request.data.get("preserve_archive"), True), description=str(request.data.get("description", "")), comments=str(request.data.get("comments", "")))
        except UnifiedImportError as exc:
            raise ValidationError({"files": [str(exc)]}) from exc
        if result["mode"] == "bundle":
            return Response({"mode": "bundle", "bundle": BundleSerializer(result["bundle"], context={"request": request}).data}, status=status.HTTP_201_CREATED)
        created = []
        for obj in result.get("created", []):
            if isinstance(obj, Certificate): data = CertificateSerializer(obj, context={"request": request}).data
            elif isinstance(obj, PrivateKey): data = PrivateKeySerializer(obj, context={"request": request}).data
            else: data = CSRSerializer(obj, context={"request": request}).data
            created.append({"type": obj._meta.model_name, "object": data})
        return Response({"mode": "objects", "created": created, "reused_ca_ids": [obj.pk for obj in result.get("reused", [])], "bundle_ids": [obj.pk for obj in result.get("bundles", [])]}, status=status.HTTP_201_CREATED)
