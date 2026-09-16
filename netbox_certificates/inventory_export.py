"""One bounded-memory archive for selected cryptographic and metadata types."""
import json
import tempfile
import zipfile

from django import forms
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.core.serializers.json import DjangoJSONEncoder
from django.shortcuts import render
from django.views import View

from .bulk_export import EXPORT_CONFIG, _bundle_members, _material_for_object, _object_manifest, _secure_file_response, _write_member
from .empty_exports import empty_export_response
from .export_names import unique_bundle_directory
from .export_v1 import CONFIG, serialize_object
from .permissions import action_queryset, require_action_permission


TYPE_LABELS = {
    "certificate": "Certificates (including CAs)", "privatekey": "Private keys", "csr": "CSRs", "bundle": "Bundles",
    "artifactgroup": "Groups", "service": "Services", "objectlink": "Object links", "healthfinding": "Health findings",
    "alertrule": "Alert rules", "alertchannel": "Alert channels", "alertevent": "Alert history",
}


class InventoryExportForm(forms.Form):
    types = forms.MultipleChoiceField(choices=list(TYPE_LABELS.items()), widget=forms.CheckboxSelectMultiple,
                                     initial=["certificate", "privatekey", "csr", "bundle"], label="Object types")


def export_inventory(request, selected):
    querysets = {}
    for kind in selected:
        if kind in EXPORT_CONFIG:
            model, action = EXPORT_CONFIG[kind]["model"], EXPORT_CONFIG[kind]["action"]
        else:
            model, _, action, _ = CONFIG[kind]
        require_action_permission(model, request.user, action)
        queryset = action_queryset(model, request.user, action)
        if kind == "privatekey" and not request.user.is_superuser:
            raise PermissionDenied("Private-key export requires a NetBox superuser.")
        if kind == "bundle":
            if not request.user.is_superuser and queryset.filter(private_key__isnull=False).exists():
                raise PermissionDenied("The Bundle selection contains private keys and requires a NetBox superuser.")
            queryset = queryset.select_related("certificate", "private_key", "csr").prefetch_related("chain_certificates")
        querysets[kind] = queryset.order_by("pk")
    if not any(queryset.exists() for queryset in querysets.values()):
        return empty_export_response(request)
    output = tempfile.SpooledTemporaryFile(max_size=8 * 1024 * 1024, mode="w+b")
    manifest = {"format": "netbox-certificates-export-manifest", "manifest_version": 1, "plugin_version": "1.2.0",
                "object_kind": "inventory", "objects": [], "files": [], "count": 0, "sensitive": bool(set(selected) & {"privatekey", "bundle"})}
    try:
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            directories = set()
            for kind, queryset in querysets.items():
                for obj in queryset.iterator(chunk_size=200):
                    manifest["count"] += 1
                    manifest["objects"].append(_object_manifest(obj))
                    if kind in EXPORT_CONFIG:
                        if kind == "bundle":
                            directory = "bundles/" + unique_bundle_directory(obj, directories)
                            members = _bundle_members(obj, directory=directory, include_chain=True)
                        else:
                            filename, data = _material_for_object(kind, obj)
                            members = [(f"{kind}/{obj.pk}-{filename}", data, obj)]
                        for filename, data, artifact in members:
                            checksum = _write_member(archive, filename, data)
                            manifest["files"].append({"path": filename, "sha256": checksum, "artifact": _object_manifest(artifact)})
                    else:
                        # Metadata never includes private material or delivery credentials.
                        filename = f"metadata/{kind}/{obj.pk}.json"
                        data = json.dumps(serialize_object(obj, request.user), cls=DjangoJSONEncoder, ensure_ascii=False).encode("utf-8")
                        checksum = _write_member(archive, filename, data)
                        manifest["files"].append({"path": filename, "sha256": checksum})
            _write_member(archive, "manifest.json", json.dumps(manifest, ensure_ascii=False).encode("utf-8"))
        return _secure_file_response(output, "certificate-inventory.zip")
    except Exception:
        output.close()
        raise


class InventoryExportView(LoginRequiredMixin, View):
    def get(self, request):
        return render(request, "netbox_certificates/inventory_export.html", {"form": InventoryExportForm()})

    def post(self, request):
        form = InventoryExportForm(request.POST)
        if form.is_valid():
            from .services.encryption import PrivateKeyEncryptionError
            try:
                return export_inventory(request, form.cleaned_data["types"])
            except PrivateKeyEncryptionError:
                form.add_error(None, "Stored private-key material could not be decrypted. No archive was returned.")
        return render(request, "netbox_certificates/inventory_export.html", {"form": form})
