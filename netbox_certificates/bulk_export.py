import hashlib
import json
import tempfile
import zipfile
from datetime import datetime, timezone

from django.http import FileResponse, Http404, HttpResponse, QueryDict
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin

from .artifact_filtersets_v1 import (
    BundleV1FilterSet,
    CertificateV1FilterSet,
    CSRV1FilterSet,
    PrivateKeyV1FilterSet,
)
from .models import Bundle, Certificate, CSR, PrivateKey
from .permissions import action_queryset
from .services.encryption import PrivateKeyEncryptionError, decrypt_private_key
from .services.chain import ordered_chain


EXPORT_CONFIG = {
    "certificate": {
        "model": Certificate,
        "action": "download",
        "filterset": CertificateV1FilterSet,
        "filename": "certificates-material.zip",
    },
    "privatekey": {
        "model": PrivateKey,
        "action": "download",
        "filterset": PrivateKeyV1FilterSet,
        "filename": "private-keys-material.zip",
    },
    "csr": {
        "model": CSR,
        "action": "download",
        "filterset": CSRV1FilterSet,
        "filename": "csrs-material.zip",
    },
    "bundle": {
        "model": Bundle,
        "action": "export",
        "filterset": BundleV1FilterSet,
        "filename": "bundles-material.zip",
    },
}


def _artifact_token(obj):
    if isinstance(obj, Certificate):
        value = getattr(obj, "fingerprint_sha256", "")
    elif isinstance(obj, PrivateKey):
        value = getattr(obj, "public_key_fingerprint", "")
    elif isinstance(obj, CSR):
        value = getattr(obj, "fingerprint_sha256", "")
    else:
        value = getattr(obj, "identity_fingerprint", "") or ""
    value = "".join(ch for ch in str(value).lower() if ch.isalnum())
    return value[:12] or f"{obj.pk:012x}"


def _artifact_filename(obj, extension):
    prefix = {
        Certificate: "certificate",
        PrivateKey: "private-key",
        CSR: "csr",
    }.get(obj.__class__, obj._meta.model_name.replace("_", "-"))
    return f"{prefix}-{_artifact_token(obj)}{extension}"


def _write_member(archive, name, data):
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = 0o600 << 16
    archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    return hashlib.sha256(data).hexdigest()


def _material_for_object(kind, obj):
    if kind == "certificate":
        return _artifact_filename(obj, ".crt"), obj.material.encode("ascii")
    if kind == "privatekey":
        return _artifact_filename(obj, ".key"), decrypt_private_key(obj.encrypted_material)
    if kind == "csr":
        return _artifact_filename(obj, ".csr"), obj.material.encode("ascii")
    raise ValueError(f"Unsupported artifact kind: {kind}")


def _bundle_members(bundle):
    prefix = f"bundle-{_artifact_token(bundle)}"
    members = []
    if bundle.certificate is not None:
        members.append(
            (f"{prefix}/{_artifact_filename(bundle.certificate, '.crt')}", bundle.certificate.material.encode("ascii"), bundle.certificate)
        )
    if bundle.private_key is not None:
        members.append(
            (f"{prefix}/{_artifact_filename(bundle.private_key, '.key')}", decrypt_private_key(bundle.private_key.encrypted_material), bundle.private_key)
        )
    if bundle.csr is not None:
        members.append(
            (f"{prefix}/{_artifact_filename(bundle.csr, '.csr')}", bundle.csr.material.encode("ascii"), bundle.csr)
        )

    chain = []
    if bundle.certificate is not None:
        chain.extend(ordered_chain(bundle.certificate))
    existing = {certificate.pk for certificate in chain}
    for certificate in bundle.chain_certificates.all():
        if certificate.pk not in existing:
            chain.append(certificate)
            existing.add(certificate.pk)

    for index, certificate in enumerate(chain, start=1):
        members.append(
            (
                f"{prefix}/chain/{index:02d}-{_artifact_filename(certificate, '.crt')}",
                certificate.material.encode("ascii"),
                certificate,
            )
        )
    return members


def _filtered_query_data(filterset_class, request, forced_filters=None):
    """
    Build query data solely from real FilterSet fields.

    NetBox list pages add presentation/query-state parameters (sorting, pagination,
    columns, return URLs, etc.). Passing those raw parameters into the exporter was
    the source of the 0.5.0 "Invalid export filters" failure.
    """
    allowed = set(filterset_class.base_filters.keys()) | {"filter", "filter_id"}
    data = QueryDict("", mutable=True)
    for key in allowed:
        for value in request.GET.getlist(key):
            data.appendlist(key, value)
    for key, value in (forced_filters or {}).items():
        data.setlist(key, value if isinstance(value, (list, tuple)) else [value])
    return data


def apply_current_filters(filterset_class, request, queryset, forced_filters=None):
    data = _filtered_query_data(filterset_class, request, forced_filters=forced_filters)
    filterset = filterset_class(data or None, queryset=queryset)
    if not filterset.is_valid():
        return None, filterset.errors, data
    return filterset.qs.order_by("pk"), None, data


def _object_manifest(obj):
    return {
        "id": obj.pk,
        "type": obj._meta.label_lower,
        "display": str(obj),
        "fingerprint_sha256": getattr(obj, "fingerprint_sha256", None),
        "public_key_fingerprint": getattr(obj, "public_key_fingerprint", None),
    }


def _secure_file_response(fileobj, filename):
    fileobj.seek(0)
    response = FileResponse(fileobj, as_attachment=True, filename=filename, content_type="application/zip")
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


class BulkMaterialExportView(LoginRequiredMixin, View):
    """Export the authorized material queryset represented by the current list filters."""

    spool_limit = 8 * 1024 * 1024
    forced_filters = None

    def get(self, request, kind):
        config = EXPORT_CONFIG.get(kind)
        if config is None:
            raise Http404("Unknown material export type.")

        queryset = action_queryset(config["model"], request.user, config["action"])
        if kind == "bundle":
            queryset = queryset.select_related("certificate", "private_key", "csr").prefetch_related("chain_certificates")

        queryset, errors, filter_data = apply_current_filters(
            config["filterset"],
            request,
            queryset,
            forced_filters=self.forced_filters,
        )
        if errors is not None:
            return HttpResponse(
                f"Invalid export filters: {errors}",
                status=400,
                content_type="text/plain; charset=utf-8",
            )
        if not queryset.exists():
            raise Http404("No objects are available for export with your permissions and current filters.")

        # Defense in depth: a material-export permission does not by itself grant
        # bulk extraction of plaintext private keys. Preserve the plugin's
        # sensitive-operation superuser overlay for both direct key exports and
        # Bundle archives which contain a private key.
        if kind == "privatekey" and not request.user.is_superuser:
            return HttpResponse(
                "Private-key material export requires a NetBox superuser.",
                status=403,
                content_type="text/plain; charset=utf-8",
            )
        if kind == "bundle" and not request.user.is_superuser and queryset.filter(private_key__isnull=False).exists():
            return HttpResponse(
                "The filtered Bundle export includes private-key material and requires a NetBox superuser.",
                status=403,
                content_type="text/plain; charset=utf-8",
            )

        output = tempfile.SpooledTemporaryFile(max_size=self.spool_limit, mode="w+b")
        manifest = {
            "format": "netbox-certificates-export-manifest",
            "manifest_version": 1,
            "plugin_version": "1.0.5",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "object_kind": kind,
            "filters": {key: filter_data.getlist(key) for key in filter_data.keys()},
            "objects": [],
            "files": [],
            "sensitive": kind in {"privatekey", "bundle"},
        }

        try:
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                if kind == "bundle":
                    for bundle in queryset.iterator(chunk_size=100):
                        object_entry = _object_manifest(bundle)
                        object_entry["files"] = []
                        for filename, data, artifact in _bundle_members(bundle):
                            checksum = _write_member(archive, filename, data)
                            file_entry = {
                                "path": filename,
                                "sha256": checksum,
                                "artifact": _object_manifest(artifact),
                            }
                            manifest["files"].append(file_entry)
                            object_entry["files"].append(filename)
                        manifest["objects"].append(object_entry)
                else:
                    for obj in queryset.iterator(chunk_size=200):
                        filename, data = _material_for_object(kind, obj)
                        checksum = _write_member(archive, filename, data)
                        manifest["objects"].append(_object_manifest(obj))
                        manifest["files"].append({"path": filename, "sha256": checksum})

                manifest["count"] = len(manifest["objects"])
                _write_member(
                    archive,
                    "manifest.json",
                    json.dumps(manifest, indent=2, sort_keys=True, default=str).encode("utf-8"),
                )
        except PrivateKeyEncryptionError:
            output.close()
            return HttpResponse(
                "Export aborted because at least one stored private key could not be decrypted. No partial archive was returned.",
                status=409,
                content_type="text/plain; charset=utf-8",
            )
        except Exception:
            output.close()
            raise

        return _secure_file_response(output, config["filename"])


class CertificateAuthorityMaterialExportView(BulkMaterialExportView):
    forced_filters = {"is_ca": "true"}

    def get(self, request):
        return super().get(request, "certificate")

class SingleBundleArchiveExportView(LoginRequiredMixin, View):
    """Export one Bundle as ZIP/TAR with a manifest.

    Existing PFX/PKCS#12 requests are delegated to the established pre-1.0
    BundleExportView so its password validation and sensitive-operation checks
    remain unchanged.
    """

    spool_limit = 8 * 1024 * 1024

    @staticmethod
    def _requested_format(request):
        return str(request.POST.get("format") or request.GET.get("format") or "zip").lower()

    def _delegate_legacy(self, request, pk):
        from .views import BundleExportView as LegacyBundleExportView
        return LegacyBundleExportView.as_view()(request, pk=pk)

    def _bundle(self, request, pk):
        return (
            action_queryset(Bundle, request.user, "export")
            .select_related("certificate", "private_key", "csr")
            .prefetch_related("chain_certificates")
            .filter(pk=pk)
            .first()
        )

    def _manifest_and_members(self, bundle):
        members = _bundle_members(bundle)
        manifest = {
            "format": "netbox-certificates-export-manifest",
            "manifest_version": 1,
            "plugin_version": "1.0.5",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "object_kind": "bundle",
            "count": 1,
            "objects": [_object_manifest(bundle)],
            "files": [],
            "sensitive": bool(bundle.private_key_id),
        }
        output_members = []
        for filename, data, artifact in members:
            manifest["files"].append(
                {
                    "path": filename,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "artifact": _object_manifest(artifact),
                }
            )
            output_members.append((filename, data))
        return manifest, output_members

    def _zip(self, bundle):
        manifest, members = self._manifest_and_members(bundle)
        output = tempfile.SpooledTemporaryFile(max_size=self.spool_limit, mode="w+b")
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            for filename, data in members:
                _write_member(archive, filename, data)
            _write_member(
                archive,
                "manifest.json",
                json.dumps(manifest, indent=2, sort_keys=True, default=str).encode("utf-8"),
            )
        return _secure_file_response(output, f"bundle-{_artifact_token(bundle)}.zip")

    def _tar(self, bundle):
        import io
        import tarfile

        manifest, members = self._manifest_and_members(bundle)
        manifest_data = json.dumps(manifest, indent=2, sort_keys=True, default=str).encode("utf-8")
        output = tempfile.SpooledTemporaryFile(max_size=self.spool_limit, mode="w+b")
        with tarfile.open(fileobj=output, mode="w") as archive:
            for filename, data in [*members, ("manifest.json", manifest_data)]:
                info = tarfile.TarInfo(filename)
                info.size = len(data)
                info.mode = 0o600
                info.mtime = int(datetime.now(timezone.utc).timestamp())
                archive.addfile(info, io.BytesIO(data))
        output.seek(0)
        response = FileResponse(
            output,
            as_attachment=True,
            filename=f"bundle-{_artifact_token(bundle)}.tar",
            content_type="application/x-tar",
        )
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response["Pragma"] = "no-cache"
        response["X-Content-Type-Options"] = "nosniff"
        return response

    def _archive(self, request, pk):
        bundle = self._bundle(request, pk)
        if bundle is None:
            raise Http404("Bundle not found or export permission denied.")
        if bundle.private_key_id and not request.user.is_superuser:
            return HttpResponse(
                "Bundle archives containing private-key material require a NetBox superuser.",
                status=403,
                content_type="text/plain; charset=utf-8",
            )
        requested_format = self._requested_format(request)
        if requested_format in {"tar", "tarfile"}:
            return self._tar(bundle)
        return self._zip(bundle)

    def get(self, request, pk):
        requested_format = self._requested_format(request)
        if requested_format in {"pfx", "pkcs12", "pkcs#12"}:
            return self._delegate_legacy(request, pk)
        return self._archive(request, pk)

    def post(self, request, pk):
        requested_format = self._requested_format(request)
        if "password" in request.POST or requested_format in {"pfx", "pkcs12", "pkcs#12"}:
            return self._delegate_legacy(request, pk)
        return self._archive(request, pk)
