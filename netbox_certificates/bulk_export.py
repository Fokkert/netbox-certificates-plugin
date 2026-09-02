from __future__ import annotations

import tempfile
import zipfile
from urllib.parse import urlencode

from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.views import View

from .filtersets import BundleFilterSet, CertificateFilterSet, CSRFilterSet, PrivateKeyFilterSet
from .models import Bundle, Certificate, CertificateAuthority, CSR, PrivateKey
from .permissions import action_queryset
from .services.chain import ordered_chain
from .services.encryption import PrivateKeyEncryptionError, decrypt_private_key


EXPORT_CONFIG = {
    "certificate": {
        "model": Certificate,
        "action": "download",
        "filterset": CertificateFilterSet,
        "filename": "certificates-material.zip",
    },
    "privatekey": {
        "model": PrivateKey,
        "action": "download",
        "filterset": PrivateKeyFilterSet,
        "filename": "private-keys-material.zip",
    },
    "csr": {
        "model": CSR,
        "action": "download",
        "filterset": CSRFilterSet,
        "filename": "csrs-material.zip",
    },
    "bundle": {
        "model": Bundle,
        "action": "export",
        "filterset": BundleFilterSet,
        "filename": "bundles-material.zip",
    },
}


def _artifact_token(obj):
    if isinstance(obj, Certificate):
        value = obj.fingerprint_sha256
    elif isinstance(obj, PrivateKey):
        value = obj.public_key_fingerprint
    elif isinstance(obj, CSR):
        value = obj.fingerprint_sha256
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
            (f"{prefix}/{_artifact_filename(bundle.certificate, '.crt')}", bundle.certificate.material.encode("ascii"))
        )
    if bundle.private_key is not None:
        members.append(
            (f"{prefix}/{_artifact_filename(bundle.private_key, '.key')}", decrypt_private_key(bundle.private_key.encrypted_material))
        )
    if bundle.csr is not None:
        members.append((f"{prefix}/{_artifact_filename(bundle.csr, '.csr')}", bundle.csr.material.encode("ascii")))

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
            )
        )
    return members


def _apply_filters(kind, request, queryset):
    filterset_class = EXPORT_CONFIG[kind]["filterset"]
    filterset = filterset_class(request.GET or None, queryset=queryset)
    if not filterset.is_valid():
        return None, filterset.errors
    return filterset.qs.order_by("pk"), None


def _secure_file_response(fileobj, filename):
    fileobj.seek(0)
    response = FileResponse(fileobj, as_attachment=True, filename=filename, content_type="application/zip")
    response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
    response["Pragma"] = "no-cache"
    response["X-Content-Type-Options"] = "nosniff"
    return response


class BulkMaterialExportView(LoginRequiredMixin, View):
    """Export all authorized cryptographic material matching the current list filters."""

    spool_limit = 8 * 1024 * 1024

    def get(self, request, kind):
        config = EXPORT_CONFIG.get(kind)
        if config is None:
            raise Http404("Unknown bulk export type.")

        queryset = action_queryset(config["model"], request.user, config["action"])
        if kind == "bundle":
            queryset = queryset.select_related("certificate", "private_key", "csr").prefetch_related("chain_certificates")

        queryset, errors = _apply_filters(kind, request, queryset)
        if errors is not None:
            return HttpResponse(f"Invalid export filters: {errors}", status=400, content_type="text/plain; charset=utf-8")
        if not queryset.exists():
            raise Http404("No objects are available for material export with your permissions and current filters.")

        output = tempfile.SpooledTemporaryFile(max_size=self.spool_limit, mode="w+b")
        try:
            with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
                if kind == "bundle":
                    for bundle in queryset.iterator(chunk_size=100):
                        for filename, data in _bundle_members(bundle):
                            _write_member(archive, filename, data)
                else:
                    for obj in queryset.iterator(chunk_size=200):
                        filename, data = _material_for_object(kind, obj)
                        _write_member(archive, filename, data)
        except PrivateKeyEncryptionError:
            output.close()
            return HttpResponse(
                "Bulk export aborted because at least one stored private key could not be decrypted. No partial archive was returned.",
                status=409,
                content_type="text/plain; charset=utf-8",
            )
        except Exception:
            output.close()
            raise

        return _secure_file_response(output, config["filename"])


class CertificateAuthorityLegacyRedirectView(LoginRequiredMixin, View):
    """
    Retire the dedicated Certificate Authority UI without breaking old links.

    CA identities remain an internal chain-resolution model and remain available
    through the REST API. Old web URLs now lead to Certificate inventory views.
    """

    def get(self, request, pk=None):
        certificate_url = reverse("plugins:netbox_certificates:certificate_list")
        if pk is None:
            return redirect(f"{certificate_url}?{urlencode({'is_ca': 'true'})}")

        if not action_queryset(CertificateAuthority, request.user, "view").filter(pk=pk).exists():
            raise Http404("Certificate Authority identity not found.")
        return redirect(f"{certificate_url}?{urlencode({'authority': pk})}")

    post = get
