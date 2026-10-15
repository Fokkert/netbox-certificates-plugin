"""Administrator UI for portable backups and metadata merge imports."""
import io

from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect, render
from django.views import View

from .bulk_export import _secure_file_response
from .constants import MAX_UPLOAD_BYTES
from .services.backup import BackupError, require_backup_user
from .services.metadata_import import import_metadata


class MetadataImportForm(forms.Form):
    upload = forms.FileField(label="Groups/Services export (ZIP or JSON)")


def read_upload(upload):
    data = upload.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise BackupError("Upload exceeds 64 MiB.")
    return data


def backup_response(data, password):
    response = _secure_file_response(io.BytesIO(data), "netbox-certificates-backup." + ("nbcbak" if password else "zip"))
    if password:
        response["Content-Type"] = "application/octet-stream"
    return response


class ObjectRestoreView(LoginRequiredMixin, View):
    """Merge only the object type of the page which initiated restoration."""

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            require_backup_user(request.user)
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, kind):
        return self.page(request, kind, MetadataImportForm())

    def post(self, request, kind):
        form = MetadataImportForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                result = import_metadata(read_upload(form.cleaned_data["upload"]), request.user, kind=kind)
                messages.success(request, f"Restored {result['imported']} objects.")
                for warning in result["warnings"]:
                    messages.warning(request, warning)
                return redirect(f"plugins:netbox_certificates:{kind}_list")
            except BackupError as exc:
                form.add_error(None, str(exc))
        return self.page(request, kind, form)

    @staticmethod
    def page(request, kind, form):
        label = "Services" if kind == "service" else "Groups"
        form.fields["upload"].label = f"{label} backup (ZIP or JSON)"
        return render(request, "netbox_certificates/object_restore.html", {
            "form": form, "label": label, "list_route": f"plugins:netbox_certificates:{kind}_list",
        })
