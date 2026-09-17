from .empty_exports import empty_export_response
import hashlib
import json
import tempfile
import zipfile
from datetime import datetime, timezone

from django.http import FileResponse, Http404, HttpResponse, QueryDict
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render
from netbox_certificates.version import __version__

from .artifact_filtersets_v1 import (
    BundleV1FilterSet,
    CertificateV1FilterSet,
    CSRV1FilterSet,
    PrivateKeyV1FilterSet,
)
from .models import Bundle, Certificate, CSR, PrivateKey
from .export_names import bundle_export_name, pfx_export_name, unique_bundle_directory
from .permissions import action_queryset, require_action_permission
from .services.encryption import PrivateKeyEncryptionError, decrypt_private_key
from .services.chain import ordered_chain
from .services.pkcs12_export import build_pfx


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


def _bundle_members(bundle, *, include_chain=True, export_pfx=False, password="", protect_pfx=True, directory=None):
    prefix = directory or bundle_export_name(bundle)
    members = []
    if export_pfx:
        chain = _bundle_chain(bundle) if include_chain else []
        data = build_pfx(bundle, password if protect_pfx else "", chain,
                         allow_unencrypted=not protect_pfx)
        members.append((f"{prefix}/{pfx_export_name(bundle)}", data, bundle.certificate))
    if bundle.certificate is not None and not export_pfx:
        members.append(
            (f"{prefix}/{_artifact_filename(bundle.certificate, '.crt')}", bundle.certificate.material.encode("ascii"), bundle.certificate)
        )
    if bundle.private_key is not None and not export_pfx:
        members.append(
            (f"{prefix}/{_artifact_filename(bundle.private_key, '.key')}", decrypt_private_key(bundle.private_key.encrypted_material), bundle.private_key)
        )
    if bundle.csr is not None:
        members.append(
            (f"{prefix}/{_artifact_filename(bundle.csr, '.csr')}", bundle.csr.material.encode("ascii"), bundle.csr)
        )

    for index, certificate in enumerate(_bundle_chain(bundle) if include_chain and not export_pfx else [], start=1):
        members.append((f"{prefix}/chain/{index:02d}-{_artifact_filename(certificate, '.crt')}",
                        certificate.material.encode("ascii"), certificate))
    return members


def _bundle_chain(bundle):
    chain = []
    if bundle.certificate is not None:
        chain.extend(ordered_chain(bundle.certificate))
    existing = {certificate.pk for certificate in chain}
    for certificate in bundle.chain_certificates.all():
        if certificate.pk not in existing:
            chain.append(certificate)
            existing.add(certificate.pk)

    return chain


def _filtered_query_data(filterset_class, request, forced_filters=None):
    """
    Build query data solely from real FilterSet fields.

    NetBox list pages add presentation/query-state parameters (sorting, pagination,
    columns, return URLS, etc.). Passing those raw parameters into the exporter was
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
    filterset = filterset_class(data, queryset=queryset, request=request)
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
        if kind == "bundle":
            require_action_permission(Bundle, request.user, "export")
            queryset, errors, _ = apply_current_filters(BundleV1FilterSet, request, action_queryset(Bundle, request.user, "export"))
            if errors is not None:
                return HttpResponse(f"Invalid export filters:\n{errors.as_text()}", status=400, content_type="text/plain")
            if not queryset.exists():
                return empty_export_response(request)
            from .forms import BundleExportForm
            form = BundleExportForm()
            form.fields["archive_format"].choices = (("zip", "ZIP"),)
            return render(request, "netbox_certificates/bundle_export.html", {"form": form, "bulk": True})
        return self._export(request, kind)

    def post(self, request, kind):
        if kind != "bundle":
            return HttpResponse(status=405)
        from .forms import BundleExportForm
        form = BundleExportForm(request.POST)
        form.fields["archive_format"].choices = (("zip", "ZIP"),)
        if not form.is_valid():
            return render(request, "netbox_certificates/bundle_export.html", {"form": form, "bulk": True})
        self.bundle_options = {key: form.cleaned_data[key] for key in ("include_chain", "export_pfx", "protect_pfx")}
        self.bundle_options["password"] = form.cleaned_data["pfx_password"]
        from .services.pkcs12_export import PFXExportError
        try:
            return self._export(request, kind)
        except PFXExportError as exc:
            form.add_error(None, str(exc))
            return render(request, "netbox_certificates/bundle_export.html", {"form": form, "bulk": True})

    def _export(self, request, kind):
        config = EXPORT_CONFIG.get(kind)
        if config is None:
            raise Http404("Unknown material export type.")

        require_action_permission(config["model"], request.user, config["action"])
        queryset = action_queryset(config["model"], request.user, config["action"])
        if kind == "bundle" and self.bundle_options.get("export_pfx"):
            require_action_permission(Bundle, request.user, "export_pfx")
            queryset = queryset.filter(pk__in=action_queryset(Bundle, request.user, "export_pfx"))
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
                f"Invalid export filters:\n{errors.as_text()}",
                status=400,
                content_type="text/plain; charset=utf-8",
            )
        if not queryset.exists():
            return empty_export_response(request)
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
            "plugin_version": __version__,
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
                    used_directories = set()
                    for bundle in queryset.iterator(chunk_size=100):
                        object_entry = _object_manifest(bundle)
                        object_entry["files"] = []
                        directory = unique_bundle_directory(bundle, used_directories)
                        for filename, data, artifact in _bundle_members(bundle, directory=directory, **self.bundle_options):
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

    GET renders export choices; POST produces a manifest archive using the
    selected PFX, password protection, and certificate-chain settings.
    """

    spool_limit = 8 * 1024 * 1024



    def _bundle(self, request, pk):
        return (
            action_queryset(Bundle, request.user, "export")
            .select_related("certificate", "private_key", "csr")
            .prefetch_related("chain_certificates")
            .filter(pk=pk)
            .first()
        )

    def _manifest_and_members(self, bundle):
        members = _bundle_members(bundle, **self.bundle_options)
        manifest = {
            "format": "netbox-certificates-export-manifest",
            "manifest_version": 1,
            "plugin_version": __version__,
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
        return _secure_file_response(output, bundle_export_name(bundle, ".zip"))

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
            filename=bundle_export_name(bundle, ".tar"),
            content_type="application/x-tar",
        )
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response["Pragma"] = "no-cache"
        response["X-Content-Type-Options"] = "nosniff"
        return response


    def get(self, request, pk):
        from .forms import BundleExportForm
        bundle = self._bundle(request, pk)
        if bundle is None:
            raise Http404
        return render(request, "netbox_certificates/bundle_export.html", {"object": bundle, "form": BundleExportForm()})

    def post(self, request, pk):
        from .forms import BundleExportForm
        from .services.pkcs12_export import PFXExportError
        bundle = self._bundle(request, pk)
        if bundle is None:
            raise Http404
        form = BundleExportForm(request.POST)
        if form.is_valid():
            if form.cleaned_data["export_pfx"] and not action_queryset(Bundle, request.user, "export_pfx").filter(pk=pk).exists():
                raise Http404
            if bundle.private_key_id and not request.user.is_superuser:
                return HttpResponse("Private-key export requires a NetBox superuser.", status=403)
            self.bundle_options = {key: form.cleaned_data[key] for key in ("include_chain", "export_pfx", "protect_pfx")}
            self.bundle_options["password"] = form.cleaned_data["pfx_password"]
            try:
                return self._tar(bundle) if form.cleaned_data["archive_format"] == "tar" else self._zip(bundle)
            except (PFXExportError, PrivateKeyEncryptionError) as exc:
                form.add_error(None, str(exc))
        return render(request, "netbox_certificates/bundle_export.html", {"object": bundle, "form": form})
