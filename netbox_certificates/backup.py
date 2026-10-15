"""Administrator UI for portable backups and metadata merge imports."""
import io

from django import forms
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect, render
from django.views import View

from .bulk_export import _secure_file_response
from .constants import MAX_UPLOAD_BYTES
from .services.backup import BackupError, CONFIRMATION, create_backup, require_backup_user, restore_backup
from .services.metadata_import import import_metadata


class BackupExportForm(forms.Form):
    password = forms.CharField(required=False, max_length=1024, widget=forms.PasswordInput,
                               help_text="Optional. Without a password, the ZIP contains readable private keys and alert credentials.")


class BackupRestoreForm(BackupExportForm):
    upload = forms.FileField(label="Backup file")
    confirmation = forms.CharField(label=f"Type {CONFIRMATION}", max_length=100)

    def clean_confirmation(self):
        value = self.cleaned_data["confirmation"]
        if value != CONFIRMATION:
            raise forms.ValidationError("The confirmation text does not match.")
        return value


class MetadataImportForm(forms.Form):
    upload = forms.FileField(label="Groups/Services export (ZIP or JSON)")


def read_upload(upload):
    data = upload.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise BackupError("Upload exceeds 64 MiB.")
    return data


def backup_response(data, password):
    return _secure_file_response(io.BytesIO(data), "netbox-certificates-backup." + ("nbcbak" if password else "zip"))


class BackupView(LoginRequiredMixin, View):
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            require_backup_user(request.user)
        return super().dispatch(request, *args, **kwargs)

    def get(self, request):
        return self.render(request)

    def render(self, request, action=None, form=None):
        forms_by_action = {"export": BackupExportForm(), "restore": BackupRestoreForm(), "metadata": MetadataImportForm()}
        if action in forms_by_action:
            forms_by_action[action] = form
        return render(request, "netbox_certificates/backup.html", {"forms": forms_by_action})

    def post(self, request):
        action = request.POST.get("action")
        cls = {"export": BackupExportForm, "restore": BackupRestoreForm, "metadata": MetadataImportForm}.get(action)
        if cls is None:
            return self.render(request)
        form = cls(request.POST, request.FILES)
        if form.is_valid():
            values = form.cleaned_data
            try:
                if action == "export":
                    return backup_response(create_backup(request.user, values["password"]), values["password"])
                data = read_upload(values["upload"])
                result = (restore_backup(data, request.user, values["confirmation"], values["password"])
                          if action == "restore" else import_metadata(data, request.user))
                messages.success(request, f"{result.get('restored', result.get('imported'))} objects {'restored' if action == 'restore' else 'imported'} successfully.")
                for warning in result["warnings"]:
                    messages.warning(request, warning)
                return redirect("plugins:netbox_certificates:backup")
            except (BackupError, ValueError):
                # Do not expose secret values from parsing/database exceptions.
                form.add_error(None, "Operation failed: invalid file, password, configuration, or object values. No partial changes were saved. Check that source and destination use the same plugin version.")
        return self.render(request, action, form)
