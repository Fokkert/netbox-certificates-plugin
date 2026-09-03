from __future__ import annotations

import io
import tarfile
import zipfile
from functools import partial

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import transaction
from django.db.models import Q
from django.http import Http404, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils import timezone
from django.views import View
from netbox.object_actions import AddObject, BulkDelete, BulkEdit, BulkExport, BulkRename
from netbox.views import generic
from netbox.views.generic import ObjectChangeLogView
from core.models import ObjectType

from .choices import LinkOriginChoices, LinkRelationChoices
from .constants import MAX_UPLOAD_BYTES
from .filtersets import ArtifactGroupFilterSet, BundleFilterSet, CertificateFilterSet, CSRFilterSet, PrivateKeyFilterSet
from .forms import (
    ArtifactGroupBulkEditForm, ArtifactGroupFilterForm, ArtifactGroupForm, ArtifactLinkForm, ArtifactLinkTypeForm,
    BundleArtifactFilterForm, BundleBulkEditForm, BundleExportForm, BundleForm,
    CertificateArtifactFilterForm, CertificateBulkEditForm, CertificateForm, CSRArtifactFilterForm, CSRBulkEditForm, CSRForm, CSRGenerateForm,
    ExpiryAlertConfigurationForm, PrivateKeyArtifactFilterForm, PrivateKeyBulkEditForm, PrivateKeyForm, UnifiedImportForm,
)
from .models import ArtifactGroup, ArtifactLink, Bundle, Certificate, CSR, ExpiryAlertConfiguration, ExpiryAlertEvent, PrivateKey
from .permissions import action_queryset as _action_queryset, object_allowed as _object_allowed
from .services.alerts import ExpiryAlertError, send_email, send_webhook
from .services.chain import ordered_chain, validate_chain
from .services.csr import CSRGenerationError, generate_csr
from .services.encryption import PrivateKeyEncryptionError, decrypt_private_key, encrypt_private_key
from .services.expiry import expiry_state
from .services.importing import _check_created_permission
from .services.ingest import after_artifact_save
from .services.inventory import build_inventory
from .services.parser import ArtifactParseError, parse_blob
from .services.pkcs12_export import PFXExportError, build_pfx
from .services.status import refresh_certificate_statuses
from .services.unified_import import UnifiedImportError, UploadItem, import_objects
from .tables import ArtifactGroupTable, BundleTable, CertificateTable, CSRTable, PrivateKeyTable

ARTIFACT_MODELS = {"certificate": Certificate, "privatekey": PrivateKey, "csr": CSR, "bundle": Bundle}


class ArtifactObjectChangeLogView(ObjectChangeLogView):
    pass


class CertificateStatusRefreshMixin:
    def dispatch(self, request, *args, **kwargs):
        refresh_certificate_statuses()
        return super().dispatch(request, *args, **kwargs)


def _relationship_label(other, link, is_source):
    if link.relation == LinkRelationChoices.ISSUER:
        return "Issuer" if is_source else "Issued Certificate"
    if isinstance(other, PrivateKey): return "Private Key"
    if isinstance(other, CSR): return "CSR"
    if isinstance(other, Bundle): return "Bundle"
    if isinstance(other, Certificate): return "Certificate Authority" if other.is_ca else "Certificate"
    return link.get_relation_display()


def _linked_context(obj, user):
    cryptographic_links, generic_links = [], []
    obj_ct = ContentType.objects.get_for_model(obj, for_concrete_model=False)
    crypto_relations = {LinkRelationChoices.KEY_MATCH, LinkRelationChoices.CSR_MATCH, LinkRelationChoices.ISSUER, LinkRelationChoices.BUNDLE_MEMBER}
    crypto_models = (Certificate, PrivateKey, CSR, Bundle)
    seen = set()
    for link in ArtifactLink.for_object(obj).select_related("source_type", "target_type").order_by("-pk"):
        is_source = link.source_type_id == obj_ct.pk and link.source_id == obj.pk
        other = link.target_object if is_source else link.source_object
        if other is None or not _object_allowed(user, other, "view"):
            continue
        # Keep all Bundle links (an object may legitimately appear in several Bundles),
        # but collapse duplicate key/CSR/issuer targets.
        key = (link.relation, other._meta.label_lower, other.pk)
        if key in seen:
            continue
        seen.add(key)
        can_remove = link.origin == LinkOriginChoices.MANUAL and _object_allowed(user, link, "delete")
        item = {"link": link, "other": other, "type_label": str(other._meta.verbose_name).title(), "relation_label": _relationship_label(other, link, is_source), "can_remove": can_remove}
        (cryptographic_links if link.relation in crypto_relations and isinstance(other, crypto_models) else generic_links).append(item)
    return {"linked_objects": cryptographic_links + generic_links, "cryptographic_links": cryptographic_links, "generic_links": generic_links, "can_add_link": user.has_perm("netbox_certificates.add_artifactlink")}


def _group_context(obj, user):
    if not hasattr(obj, "groups"):
        return {"visible_groups": []}
    qs = ArtifactGroup.objects.filter(pk__in=obj.groups.values_list("pk", flat=True))
    if hasattr(qs, "restrict"):
        qs = qs.restrict(user, "view")
    return {"visible_groups": qs.order_by("name")}


def _safe_chain_context(instance, user):
    result = validate_chain(instance)
    visible = set(Certificate.objects.restrict(user, "view").values_list("pk", flat=True))
    safe_checks = []
    for check in result["checks"]:
        obj = check.get("object")
        if obj is not None and obj.pk not in visible:
            safe_checks.append({"object": None, "ok": False, "message": "A chain certificate exists but is not visible to your account."})
            break
        safe_checks.append(check)
    return {**result, "checks": safe_checks}


class LinkedObjectView(generic.ObjectView):
    def get_extra_context(self, request, instance):
        return {**_linked_context(instance, request.user), **_group_context(instance, request.user)}


class CertificateListView(CertificateStatusRefreshMixin, generic.ObjectListView):
    actions = (AddObject, BulkExport, BulkEdit, BulkRename, BulkDelete)
    queryset = Certificate.objects.select_related("authority", "parent_certificate", "supersedes", "owner").prefetch_related("groups")
    table = CertificateTable
    filterset = CertificateFilterSet
    filterset_form = CertificateArtifactFilterForm
    template_name = "netbox_certificates/certificate_list.html"


class CertificateView(CertificateStatusRefreshMixin, LinkedObjectView):
    queryset = Certificate.objects.select_related("authority", "parent_certificate", "supersedes", "owner").prefetch_related("groups")
    def get_extra_context(self, request, instance):
        context = super().get_extra_context(request, instance)
        visible = _action_queryset(Certificate, request.user, "view")
        visible_bundles = _action_queryset(Bundle, request.user, "view")
        context.update({
            "expiry": expiry_state(instance),
            "chain_validation": _safe_chain_context(instance, request.user),
            "visible_parent": visible.filter(pk=instance.parent_certificate_id).first() if instance.parent_certificate_id else None,
            "visible_supersedes": visible.filter(pk=instance.supersedes_id).first() if instance.supersedes_id else None,
            "renewed_by": visible.filter(supersedes=instance).order_by("valid_from"),
            "issued_certificates": visible.filter(parent_certificate=instance).order_by("name") if instance.is_ca else visible.none(),
            "related_bundles": visible_bundles.filter(Q(certificate=instance) | Q(chain_certificates=instance)).distinct().order_by("name"),
            "can_download": _object_allowed(request.user, instance, "download"),
        })
        return context


class CertificateEditView(generic.ObjectEditView):
    queryset = Certificate.objects.all()
    form = CertificateForm
    def dispatch(self, request, *args, **kwargs):
        self.form = partial(CertificateForm, user=request.user)
        return super().dispatch(request, *args, **kwargs)


class CertificateBulkEditView(generic.BulkEditView):
    queryset = Certificate.objects.all()
    filterset = CertificateFilterSet
    table = CertificateTable
    form = CertificateBulkEditForm


class CertificateBulkRenameView(generic.BulkRenameView):
    queryset = Certificate.objects.all()
    filterset = CertificateFilterSet



class CertificateDeleteView(generic.ObjectDeleteView):
    queryset = Certificate.objects.all()
    default_return_url = "plugins:netbox_certificates:certificate_list"


class PrivateKeyListView(generic.ObjectListView):
    actions = (AddObject, BulkExport, BulkEdit, BulkRename, BulkDelete)
    queryset = PrivateKey.objects.select_related("owner").prefetch_related("groups")
    table = PrivateKeyTable
    filterset = PrivateKeyFilterSet
    filterset_form = PrivateKeyArtifactFilterForm
    template_name = "netbox_certificates/privatekey_list.html"


class PrivateKeyView(LinkedObjectView):
    queryset = PrivateKey.objects.select_related("owner").prefetch_related("groups")
    def get_extra_context(self, request, instance):
        context = super().get_extra_context(request, instance)
        context["can_download"] = _object_allowed(request.user, instance, "download")
        context["related_bundles"] = _action_queryset(Bundle, request.user, "view").filter(private_key=instance).order_by("name")
        return context


class PrivateKeyEditView(generic.ObjectEditView):
    queryset = PrivateKey.objects.all()
    form = PrivateKeyForm
    def dispatch(self, request, *args, **kwargs):
        self.form = partial(PrivateKeyForm, user=request.user)
        return super().dispatch(request, *args, **kwargs)


class PrivateKeyBulkEditView(generic.BulkEditView):
    queryset = PrivateKey.objects.all()
    filterset = PrivateKeyFilterSet
    table = PrivateKeyTable
    form = PrivateKeyBulkEditForm


class PrivateKeyBulkRenameView(generic.BulkRenameView):
    queryset = PrivateKey.objects.all()
    filterset = PrivateKeyFilterSet



class PrivateKeyDeleteView(generic.ObjectDeleteView):
    queryset = PrivateKey.objects.all()
    default_return_url = "plugins:netbox_certificates:privatekey_list"


class CSRListView(generic.ObjectListView):
    actions = (AddObject, BulkExport, BulkEdit, BulkRename, BulkDelete)
    queryset = CSR.objects.select_related("owner").prefetch_related("groups")
    table = CSRTable
    filterset = CSRFilterSet
    filterset_form = CSRArtifactFilterForm
    template_name = "netbox_certificates/csr_list.html"


class CSRView(LinkedObjectView):
    queryset = CSR.objects.select_related("owner").prefetch_related("groups")
    def get_extra_context(self, request, instance):
        context = super().get_extra_context(request, instance)
        context["can_download"] = _object_allowed(request.user, instance, "download")
        context["related_bundles"] = _action_queryset(Bundle, request.user, "view").filter(csr=instance).order_by("name")
        return context


class CSREditView(generic.ObjectEditView):
    queryset = CSR.objects.all()
    form = CSRForm
    def dispatch(self, request, *args, **kwargs):
        self.form = partial(CSRForm, user=request.user)
        return super().dispatch(request, *args, **kwargs)


class CSRBulkEditView(generic.BulkEditView):
    queryset = CSR.objects.all()
    filterset = CSRFilterSet
    table = CSRTable
    form = CSRBulkEditForm


class CSRBulkRenameView(generic.BulkRenameView):
    queryset = CSR.objects.all()
    filterset = CSRFilterSet



class CSRDeleteView(generic.ObjectDeleteView):
    queryset = CSR.objects.all()
    default_return_url = "plugins:netbox_certificates:csr_list"


class BundleListView(generic.ObjectListView):
    actions = (BulkExport, BulkEdit, BulkRename, BulkDelete)
    queryset = Bundle.objects.select_related("certificate", "private_key", "csr", "owner").prefetch_related("chain_certificates", "groups")
    table = BundleTable
    filterset = BundleFilterSet
    filterset_form = BundleArtifactFilterForm
    template_name = "netbox_certificates/bundle_list.html"


class BundleView(LinkedObjectView):
    queryset = Bundle.objects.select_related("certificate", "private_key", "csr", "owner").prefetch_related("chain_certificates", "groups")
    def get_extra_context(self, request, instance):
        context = super().get_extra_context(request, instance)
        context.update({
            "visible_certificate": instance.certificate if instance.certificate and _object_allowed(request.user, instance.certificate) else None,
            "visible_private_key": instance.private_key if instance.private_key and _object_allowed(request.user, instance.private_key) else None,
            "visible_csr": instance.csr if instance.csr and _object_allowed(request.user, instance.csr) else None,
            "visible_chain": [c for c in instance.chain_certificates.all() if _object_allowed(request.user, c)],
            "can_export": _object_allowed(request.user, instance, "export"),
            "can_export_pfx": _object_allowed(request.user, instance, "export_pfx"),
        })
        if context["visible_certificate"]:
            context["chain_validation"] = _safe_chain_context(instance.certificate, request.user)
        return context


class BundleEditView(generic.ObjectEditView):
    queryset = Bundle.objects.all()
    form = BundleForm
    def dispatch(self, request, *args, **kwargs):
        self.form = partial(BundleForm, user=request.user)
        return super().dispatch(request, *args, **kwargs)


class BundleBulkEditView(generic.BulkEditView):
    queryset = Bundle.objects.all()
    filterset = BundleFilterSet
    table = BundleTable
    form = BundleBulkEditForm


class BundleBulkRenameView(generic.BulkRenameView):
    queryset = Bundle.objects.all()
    filterset = BundleFilterSet



class BundleDeleteView(generic.ObjectDeleteView):
    queryset = Bundle.objects.all()
    default_return_url = "plugins:netbox_certificates:bundle_list"


class ArtifactGroupListView(generic.ObjectListView):
    actions = (AddObject, BulkExport, BulkEdit, BulkRename, BulkDelete)
    queryset = ArtifactGroup.objects.select_related("owner", "parent").prefetch_related(
        "children", "bundles", "certificates", "private_keys", "csrs"
    )
    table = ArtifactGroupTable
    filterset = ArtifactGroupFilterSet
    filterset_form = ArtifactGroupFilterForm
    template_name = "netbox_certificates/group_list.html"


class ArtifactGroupView(generic.ObjectView):
    queryset = ArtifactGroup.objects.select_related("owner", "parent").prefetch_related(
        "children", "bundles", "certificates", "private_keys", "csrs"
    )
    template_name = "netbox_certificates/group.html"

    def get_extra_context(self, request, instance):
        visible_groups = _action_queryset(ArtifactGroup, request.user, "view")
        return {
            "parent_group": visible_groups.filter(pk=instance.parent_id).first() if instance.parent_id else None,
            "child_groups": visible_groups.filter(parent=instance).order_by("name"),
            "bundles": _action_queryset(Bundle, request.user, "view").filter(groups=instance).order_by("name"),
            "certificates": _action_queryset(Certificate, request.user, "view").filter(groups=instance).order_by("name"),
            "private_keys": _action_queryset(PrivateKey, request.user, "view").filter(groups=instance).order_by("name"),
            "csrs": _action_queryset(CSR, request.user, "view").filter(groups=instance).order_by("name"),
        }


class ArtifactGroupEditView(generic.ObjectEditView):
    queryset = ArtifactGroup.objects.all()
    form = ArtifactGroupForm
    template_name = "generic/object_edit.html"
    def dispatch(self, request, *args, **kwargs):
        self.form = partial(ArtifactGroupForm, user=request.user)
        return super().dispatch(request, *args, **kwargs)


class ArtifactGroupBulkEditView(generic.BulkEditView):
    queryset = ArtifactGroup.objects.all()
    filterset = ArtifactGroupFilterSet
    table = ArtifactGroupTable
    form = ArtifactGroupBulkEditForm


class ArtifactGroupBulkRenameView(generic.BulkRenameView):
    queryset = ArtifactGroup.objects.all()
    filterset = ArtifactGroupFilterSet



class ArtifactGroupDeleteView(generic.ObjectDeleteView):
    queryset = ArtifactGroup.objects.all()
    default_return_url = "plugins:netbox_certificates:artifactgroup_list"


class SmartBulkDeleteView(generic.BulkDeleteView):
    single_delete_routes = {
        Certificate: ("plugins:netbox_certificates:certificate_delete", "plugins:netbox_certificates:certificate_list"),
        PrivateKey: ("plugins:netbox_certificates:privatekey_delete", "plugins:netbox_certificates:privatekey_list"),
        CSR: ("plugins:netbox_certificates:csr_delete", "plugins:netbox_certificates:csr_list"),
        Bundle: ("plugins:netbox_certificates:bundle_delete", "plugins:netbox_certificates:bundle_list"),
        ArtifactGroup: ("plugins:netbox_certificates:artifactgroup_delete", "plugins:netbox_certificates:artifactgroup_list"),
    }
    def post(self, request, **kwargs):
        if "_confirm" not in request.POST and not request.POST.get("_all"):
            pk_list = request.POST.getlist("pk")
            if len(pk_list) == 1:
                delete_route, list_route = self.single_delete_routes[self.queryset.model]
                return redirect(f"{reverse(delete_route, kwargs={'pk': int(pk_list[0])})}?return_url={reverse(list_route)}")
        return super().post(request, **kwargs)


class CertificateBulkDeleteView(SmartBulkDeleteView):
    queryset = Certificate.objects.all(); table = CertificateTable; filterset = CertificateFilterSet; default_return_url = "plugins:netbox_certificates:certificate_list"
class PrivateKeyBulkDeleteView(SmartBulkDeleteView):
    queryset = PrivateKey.objects.all(); table = PrivateKeyTable; filterset = PrivateKeyFilterSet; default_return_url = "plugins:netbox_certificates:privatekey_list"
class CSRBulkDeleteView(SmartBulkDeleteView):
    queryset = CSR.objects.all(); table = CSRTable; filterset = CSRFilterSet; default_return_url = "plugins:netbox_certificates:csr_list"
class BundleBulkDeleteView(SmartBulkDeleteView):
    queryset = Bundle.objects.all(); table = BundleTable; filterset = BundleFilterSet; default_return_url = "plugins:netbox_certificates:bundle_list"
class ArtifactGroupBulkDeleteView(SmartBulkDeleteView):
    queryset = ArtifactGroup.objects.all(); table = ArtifactGroupTable; filterset = ArtifactGroupFilterSet; default_return_url = "plugins:netbox_certificates:artifactgroup_list"


class UnifiedImportView(LoginRequiredMixin, View):
    template_name = "netbox_certificates/import_objects.html"
    def _context(self, request, form=None):
        return {"form": form or UnifiedImportForm(user=request.user), "return_url": request.GET.get("return_url") or reverse("plugins:netbox_certificates:vault")}
    def get(self, request):
        return render(request, self.template_name, self._context(request))
    def post(self, request):
        form = UnifiedImportForm(request.POST, request.FILES, user=request.user)
        if not form.is_valid():
            return render(request, self.template_name, self._context(request, form))
        uploads = form.cleaned_data["files"]
        total = sum(upload.size for upload in uploads)
        if total > MAX_UPLOAD_BYTES:
            form.add_error("files", f"Combined upload is too large ({total} bytes); limit is {MAX_UPLOAD_BYTES} bytes.")
            return render(request, self.template_name, self._context(request, form))
        allowed_kinds = {
            kind for kind, permission in {
                "certificate": "netbox_certificates.add_certificate",
                "csr": "netbox_certificates.add_csr",
                "private_key": "netbox_certificates.add_privatekey",
            }.items() if request.user.has_perm(permission)
        }
        if not allowed_kinds:
            raise PermissionDenied("You do not have permission to import certificate objects.")
        items = [UploadItem(upload.name, upload.read()) for upload in uploads]
        try:
            result = import_objects(
                uploads=items,
                allowed_kinds=allowed_kinds,
                user=request.user,
                owner=form.cleaned_data.get("owner"),
                groups=form.cleaned_data.get("groups"),
                password=form.cleaned_data.get("password") or None,
                archive_password=form.cleaned_data.get("archive_password") or None,
                import_chain=form.cleaned_data.get("import_chain", True),
                preserve_archive=form.cleaned_data.get("preserve_archive", True),
                description=form.cleaned_data.get("description", ""),
                comments=form.cleaned_data.get("comments", ""),
            )
        except (UnifiedImportError, PermissionDenied) as exc:
            form.add_error("files", str(exc))
            return render(request, self.template_name, self._context(request, form))
        if result["mode"] == "bundle":
            messages.success(request, f"Imported Bundle {result['bundle']} and linked all detected members.")
            return redirect("plugins:netbox_certificates:bundle_list")
        created = result.get("created", [])
        reused = result.get("reused", [])
        messages.success(request, f"Imported {len(created)} new object(s) and reused {len(reused)} existing CA certificate(s).")
        kinds = {obj.__class__ for obj in created}
        if kinds == {Certificate}: return redirect("plugins:netbox_certificates:certificate_list")
        if kinds == {PrivateKey}: return redirect("plugins:netbox_certificates:privatekey_list")
        if kinds == {CSR}: return redirect("plugins:netbox_certificates:csr_list")
        return redirect("plugins:netbox_certificates:vault")


class CSRGenerateView(PermissionRequiredMixin, View):
    permission_required = ("netbox_certificates.add_csr", "netbox_certificates.add_privatekey")
    template_name = "netbox_certificates/csr_generate.html"
    ku_field_names = ("ku_digital_signature", "ku_content_commitment", "ku_key_encipherment", "ku_data_encipherment", "ku_key_agreement", "ku_key_cert_sign", "ku_crl_sign")
    eku_field_names = ("eku_server_auth", "eku_client_auth", "eku_code_signing", "eku_email_protection", "eku_time_stamping", "eku_ocsp_signing")
    def _context(self, form):
        return {"form": form, "ku_fields": [form[n] for n in self.ku_field_names], "eku_fields": [form[n] for n in self.eku_field_names], "return_url": reverse("plugins:netbox_certificates:csr_list")}
    def get(self, request):
        return render(request, self.template_name, self._context(CSRGenerateForm(user=request.user)))
    def post(self, request):
        form = CSRGenerateForm(request.POST, user=request.user)
        if form.is_valid():
            d = form.cleaned_data
            try:
                key_pem, csr_pem = generate_csr(
                    common_name=d["common_name"], sans=[x.strip() for x in d.get("sans", "").splitlines() if x.strip()], key_algorithm=d["key_algorithm"], rsa_bits=int(d["rsa_bits"]), ec_curve=d["ec_curve"], signature_hash=d["signature_hash"], rsa_signature=d["rsa_signature"],
                    country=d.get("country", ""), state=d.get("state", ""), locality=d.get("locality", ""), organization=d.get("organization", ""), organizational_unit=d.get("organizational_unit", ""), street_address=d.get("street_address", ""), postal_code=d.get("postal_code", ""), subject_serial_number=d.get("subject_serial_number", ""), email=d.get("email", ""),
                    key_usages=[name for name, field in (("digital_signature", "ku_digital_signature"), ("content_commitment", "ku_content_commitment"), ("key_encipherment", "ku_key_encipherment"), ("data_encipherment", "ku_data_encipherment"), ("key_agreement", "ku_key_agreement"), ("key_cert_sign", "ku_key_cert_sign"), ("crl_sign", "ku_crl_sign")) if d.get(field)],
                    extended_key_usages=[name for name, field in (("server_auth", "eku_server_auth"), ("client_auth", "eku_client_auth"), ("code_signing", "eku_code_signing"), ("email_protection", "eku_email_protection"), ("time_stamping", "eku_time_stamping"), ("ocsp_signing", "eku_ocsp_signing")) if d.get(field)],
                    request_ca=d.get("request_ca", False), path_length=d.get("path_length"),
                )
                key_p = next(p for p in parse_blob(key_pem, filename="generated.key") if p.kind == "private_key")
                csr_p = next(p for p in parse_blob(csr_pem, filename="generated.csr") if p.kind == "csr")
            except (CSRGenerationError, ArtifactParseError, StopIteration) as exc:
                form.add_error(None, str(exc))
            else:
                with transaction.atomic():
                    key_metadata = {k: v for k, v in key_p.metadata.items() if k != "curve"}
                    key = PrivateKey.objects.create(name=(d.get("name") or d["common_name"]) + " key", source_filename="generated.key", source_format="pem", encrypted_material=encrypt_private_key(key_p.data), owner=d.get("owner"), **key_metadata)
                    _check_created_permission(request.user, key)
                    csr = CSR.objects.create(name=d.get("name") or d["common_name"], source_filename="generated.csr", source_format="pem", material=csr_p.data.decode("ascii"), owner=d.get("owner"), **csr_p.metadata)
                    _check_created_permission(request.user, csr)
                    groups = d.get("groups")
                    if groups:
                        key.groups.add(*groups); csr.groups.add(*groups)
                    after_artifact_save(key); after_artifact_save(csr)
                messages.success(request, "CSR and private key generated, encrypted at rest, grouped, and linked.")
                return redirect(csr.get_absolute_url())
        return render(request, self.template_name, self._context(form))


def _artifact_token(obj):
    if isinstance(obj, Certificate): value = obj.fingerprint_sha256
    elif isinstance(obj, PrivateKey): value = obj.public_key_fingerprint
    elif isinstance(obj, CSR): value = obj.fingerprint_sha256
    else: value = getattr(obj, "identity_fingerprint", "") or ""
    value = "".join(ch for ch in str(value).lower() if ch.isalnum())
    return value[:12] or f"{obj.pk:012x}"


def _artifact_download_filename(obj, extension):
    prefix = {Certificate: "certificate", PrivateKey: "private-key", CSR: "csr"}.get(obj.__class__, obj._meta.model_name.replace("_", "-"))
    return f"{prefix}-{_artifact_token(obj)}{extension}"


def _bundle_download_filename(obj, archive_format="zip"):
    extension = {"zip": ".zip", "tar": ".tar"}.get(archive_format)
    if extension is None: raise Http404("Unsupported archive format.")
    return f"bundle-{_artifact_token(obj)}{extension}"


def _archive_bytes(files, archive_format):
    output = io.BytesIO()
    if archive_format == "zip":
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for filename, data in files:
                info = zipfile.ZipInfo(filename); info.external_attr = 0o600 << 16
                archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
        return output.getvalue(), "application/zip"
    if archive_format == "tar":
        with tarfile.open(fileobj=output, mode="w") as archive:
            for filename, data in files:
                info = tarfile.TarInfo(name=filename); info.size, info.mtime, info.mode = len(data), 0, 0o600
                archive.addfile(info, io.BytesIO(data))
        return output.getvalue(), "application/x-tar"
    raise Http404("Unsupported archive format.")


class DownloadArtifactView(LoginRequiredMixin, View):
    def get(self, request, kind, pk):
        if kind not in {"certificate", "privatekey", "csr"}: raise Http404("Unknown downloadable artifact type.")
        model = ARTIFACT_MODELS[kind]
        try: obj = _action_queryset(model, request.user, "download").get(pk=pk)
        except model.DoesNotExist: raise Http404("Object not found.")
        try:
            if kind == "privatekey": data, filename, content_type = decrypt_private_key(obj.encrypted_material), _artifact_download_filename(obj, ".key"), "application/x-pem-file"
            elif kind == "certificate": data, filename, content_type = obj.material.encode("ascii"), _artifact_download_filename(obj, ".crt"), "application/x-pem-file"
            else: data, filename, content_type = obj.material.encode("ascii"), _artifact_download_filename(obj, ".csr"), "application/pkcs10"
        except PrivateKeyEncryptionError:
            messages.error(request, "The stored encrypted material could not be decrypted."); return redirect(obj.get_absolute_url())
        response = HttpResponse(data, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"; response["Pragma"] = "no-cache"; response["X-Content-Type-Options"] = "nosniff"
        return response


class BundleExportView(LoginRequiredMixin, View):
    template_name = "netbox_certificates/bundle_export.html"
    def _bundle(self, request, pk, action="export"):
        try: return _action_queryset(Bundle, request.user, action).select_related("certificate", "private_key", "csr").prefetch_related("chain_certificates").get(pk=pk)
        except Bundle.DoesNotExist: raise Http404("Bundle not found.")
    def _page_bundle(self, request, pk):
        for action in ("export", "export_pfx"):
            try: return self._bundle(request, pk, action)
            except Http404: pass
        raise Http404("Bundle not found.")
    def get(self, request, pk):
        bundle = self._page_bundle(request, pk)
        return render(request, self.template_name, {"object": bundle, "form": BundleExportForm(), "return_url": bundle.get_absolute_url(), "success_url": reverse("plugins:netbox_certificates:bundle_list")})
    def post(self, request, pk):
        page_bundle = self._page_bundle(request, pk); form = BundleExportForm(request.POST)
        context = lambda bundle: {"object": bundle, "form": form, "return_url": bundle.get_absolute_url(), "success_url": reverse("plugins:netbox_certificates:bundle_list")}
        if not form.is_valid(): return render(request, self.template_name, context(page_bundle))
        d = form.cleaned_data; bundle = self._bundle(request, pk, "export_pfx" if d.get("export_pfx") else "export")
        if sum(member is not None for member in (bundle.certificate, bundle.private_key, bundle.csr)) < 2:
            form.add_error(None, "A Bundle must contain at least two matching primary objects before export."); return render(request, self.template_name, context(bundle))
        try:
            if d.get("export_pfx"):
                if bundle.certificate is None or bundle.private_key is None: raise PFXExportError("PFX export requires a certificate and matching private key.")
                chain = []
                if d.get("include_chain"):
                    chain = ordered_chain(bundle.certificate); chain.extend(c for c in bundle.chain_certificates.all() if c.pk not in {x.pk for x in chain})
                files = [(_artifact_download_filename(bundle.certificate, ".pfx"), build_pfx(bundle, d["pfx_password"], chain_certificates=chain))]
                if bundle.csr: files.append((_artifact_download_filename(bundle.csr, ".csr"), bundle.csr.material.encode("ascii")))
            else:
                files = []
                if bundle.certificate: files.append((_artifact_download_filename(bundle.certificate, ".crt"), bundle.certificate.material.encode("ascii")))
                if bundle.private_key: files.append((_artifact_download_filename(bundle.private_key, ".key"), decrypt_private_key(bundle.private_key.encrypted_material)))
                if bundle.csr: files.append((_artifact_download_filename(bundle.csr, ".csr"), bundle.csr.material.encode("ascii")))
                if d.get("include_chain"):
                    chain = ordered_chain(bundle.certificate) if bundle.certificate else []; seen = {c.pk for c in chain}; chain.extend(c for c in bundle.chain_certificates.all() if c.pk not in seen)
                    used = {name for name, _ in files}
                    for cert in chain:
                        filename = _artifact_download_filename(cert, ".crt")
                        if filename not in used: files.append((filename, cert.material.encode("ascii"))); used.add(filename)
            data, content_type = _archive_bytes(files, d["archive_format"])
        except (PFXExportError, PrivateKeyEncryptionError) as exc:
            form.add_error(None, str(exc)); return render(request, self.template_name, context(bundle))
        response = HttpResponse(data, content_type=content_type)
        response["Content-Disposition"] = f'attachment; filename="{_bundle_download_filename(bundle, d["archive_format"])}"'
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"; response["Pragma"] = "no-cache"; response["X-Content-Type-Options"] = "nosniff"
        return response


class ExpirationDashboardView(CertificateStatusRefreshMixin, PermissionRequiredMixin, View):
    permission_required = "netbox_certificates.view_certificate"
    template_name = "netbox_certificates/expiration_dashboard.html"
    def get(self, request):
        qs = _action_queryset(Certificate, request.user, "view").order_by("valid_to")
        states = [(cert, expiry_state(cert)) for cert in qs]
        counts = {key: sum(1 for _, state in states if state["level"] == key) for key in ("healthy", "warning", "critical", "expired", "unknown")}
        upcoming = [(cert, state) for cert, state in states if state["level"] in {"warning", "critical"}][:50]
        return render(request, self.template_name, {"counts": counts, "upcoming": upcoming})


class InventoryView(CertificateStatusRefreshMixin, LoginRequiredMixin, View):
    template_name = "netbox_certificates/inventory.html"
    def get(self, request):
        inventory = build_inventory(request.user)
        return render(request, self.template_name, {"bundle_groups": inventory["groups"], "unbundled": inventory["unbundled"], "counts": inventory["counts"]})


class ExpirationAlertsView(LoginRequiredMixin, View):
    template_name = "netbox_certificates/expiration_alerts.html"
    def _allowed(self, user):
        return getattr(user, "is_superuser", False) or user.has_perm("netbox_certificates.change_expiryalertconfiguration") or user.has_perm("netbox_certificates.add_expiryalertconfiguration")
    def _test_allowed(self, user): return self._allowed(user) or user.has_perm("netbox_certificates.test_expiryalertconfiguration")
    def _context(self, request, form=None):
        config = ExpiryAlertConfiguration.objects.first(); instance = config or ExpiryAlertConfiguration()
        if form is None: form = ExpiryAlertConfigurationForm(instance=instance)
        visible_certs = _action_queryset(Certificate, request.user, "view")
        recent_events = ExpiryAlertEvent.objects.filter(certificate__in=visible_certs).select_related("certificate").order_by("-last_attempt_at", "-created")[:50]
        return {"form": form, "config": config, "recent_events": recent_events, "return_url": reverse("plugins:netbox_certificates:expiration_dashboard")}
    def get(self, request):
        if not self._allowed(request.user): raise PermissionDenied("You do not have permission to manage expiration alerts.")
        return render(request, self.template_name, self._context(request))
    def post(self, request):
        if not self._allowed(request.user): raise PermissionDenied("You do not have permission to manage expiration alerts.")
        action = request.POST.get("_action", "save"); config = ExpiryAlertConfiguration.objects.first() or ExpiryAlertConfiguration()
        form = ExpiryAlertConfigurationForm(request.POST, instance=config, require_email=action == "test_email", require_webhook=action == "test_webhook")
        if not form.is_valid(): return render(request, self.template_name, self._context(request, form=form))
        config = form.save()
        if action == "save": messages.success(request, "Expiration alert configuration saved."); return redirect("plugins:netbox_certificates:alertrule_list")
        if not self._test_allowed(request.user): raise PermissionDenied("You do not have permission to test expiration alerts.")
        now = timezone.now()
        try:
            if action == "test_email":
                result = send_email(config, test=True); config.email_last_test_at = now; config.email_last_test_success = True; config.email_last_test_message = result[:500]
                config.save(update_fields=("email_last_test_at", "email_last_test_success", "email_last_test_message", "last_updated")); messages.success(request, "Email test succeeded: " + result)
            elif action == "test_webhook":
                status, result = send_webhook(config, test=True); config.webhook_last_test_at = now; config.webhook_last_test_success = True; config.webhook_last_test_message = result[:500]
                config.save(update_fields=("webhook_last_test_at", "webhook_last_test_success", "webhook_last_test_message", "last_updated")); messages.success(request, f"Webhook test succeeded (HTTP {status}).")
            else: messages.error(request, "Unknown expiration-alert action.")
        except Exception as exc:
            message = str(exc) if isinstance(exc, ExpiryAlertError) else f"{action.replace('_', ' ').title()} failed: {exc}"
            if action == "test_email":
                config.email_last_test_at = now; config.email_last_test_success = False; config.email_last_test_message = message[:500]
                config.save(update_fields=("email_last_test_at", "email_last_test_success", "email_last_test_message", "last_updated"))
            elif action == "test_webhook":
                config.webhook_last_test_at = now; config.webhook_last_test_success = False; config.webhook_last_test_message = message[:500]
                config.save(update_fields=("webhook_last_test_at", "webhook_last_test_success", "webhook_last_test_message", "last_updated"))
            messages.error(request, message)
        return redirect("plugins:netbox_certificates:alertrule_list")


class ArtifactLinkCreateView(LoginRequiredMixin, View):
    template_name = "netbox_certificates/link_add.html"
    def _source(self, kind, pk, user):
        if kind not in ARTIFACT_MODELS: raise Http404("Unknown artifact type.")
        model = ARTIFACT_MODELS[kind]
        try: return model.objects.restrict(user, "view").get(pk=pk)
        except model.DoesNotExist: raise Http404("Object not found.")
    def _object_type(self, value):
        try: return ObjectType.objects.filter(public=True).get(pk=int(value))
        except (ObjectType.DoesNotExist, TypeError, ValueError): raise Http404("Object type not found.")
    def get(self, request, kind, pk):
        source = self._source(kind, pk, request.user)
        if not request.user.has_perm("netbox_certificates.add_artifactlink"): raise PermissionDenied
        type_id = request.GET.get("target_type")
        if not type_id: return render(request, self.template_name, {"type_form": ArtifactLinkTypeForm(), "source": source, "return_url": source.get_absolute_url()})
        target_type = self._object_type(type_id)
        return render(request, self.template_name, {"form": ArtifactLinkForm(target_type=target_type, user=request.user), "source": source, "target_type": target_type, "return_url": source.get_absolute_url()})
    def post(self, request, kind, pk):
        source = self._source(kind, pk, request.user)
        if not request.user.has_perm("netbox_certificates.add_artifactlink"): raise PermissionDenied
        if request.POST.get("choose_type"):
            type_form = ArtifactLinkTypeForm(request.POST)
            if type_form.is_valid(): return redirect(f"{request.path}?target_type={type_form.cleaned_data['target_type'].pk}")
            return render(request, self.template_name, {"type_form": type_form, "source": source, "return_url": source.get_absolute_url()})
        target_type = self._object_type(request.POST.get("target_type")); form = ArtifactLinkForm(request.POST, target_type=target_type, user=request.user)
        if form.is_valid():
            target = form.cleaned_data["target"]
            if source._meta.label_lower == target._meta.label_lower and source.pk == target.pk:
                form.add_error("target", "An object cannot be linked to itself.")
            else:
                with transaction.atomic():
                    lookup = {"source_type": ContentType.objects.get_for_model(source, for_concrete_model=False), "source_id": source.pk, "target_type": ContentType.objects.get_for_model(target, for_concrete_model=False), "target_id": target.pk, "relation": form.cleaned_data["relation"]}
                    existing = ArtifactLink.objects.filter(**lookup).first()
                    if existing:
                        if not _object_allowed(request.user, existing, "change"): raise PermissionDenied("You do not have permission to change this link.")
                        existing.origin = LinkOriginChoices.MANUAL; existing.note = form.cleaned_data.get("note", ""); existing.active = True; existing.save(update_fields=("origin", "note", "active"))
                    else:
                        link = ArtifactLink.objects.create(**lookup, origin=LinkOriginChoices.MANUAL, note=form.cleaned_data.get("note", ""), active=True)
                        if not _object_allowed(request.user, link, "add"): raise PermissionDenied("The new link does not satisfy your object permission constraints.")
                messages.success(request, f"Linked {source} to {target}."); return redirect(source.get_absolute_url())
        return render(request, self.template_name, {"form": form, "source": source, "target_type": target_type, "return_url": source.get_absolute_url()})


class ArtifactLinkRemoveView(LoginRequiredMixin, View):
    template_name = "netbox_certificates/link_remove.html"
    def _link(self, pk, user):
        link = get_object_or_404(ArtifactLink, pk=pk)
        for obj in (link.source_object, link.target_object):
            if obj is not None and not _object_allowed(user, obj, "view"): raise Http404("Object not found.")
        if link.origin != LinkOriginChoices.MANUAL: raise PermissionDenied("Cryptographic relationships are managed automatically and cannot be removed.")
        if not _object_allowed(user, link, "delete"): raise PermissionDenied
        return link
    def _return_url(self, link):
        for obj in (link.source_object, link.target_object):
            if obj is not None and obj.__class__ in ARTIFACT_MODELS.values() and hasattr(obj, "get_absolute_url"): return obj.get_absolute_url()
        return reverse("plugins:netbox_certificates:certificate_list")
    def get(self, request, pk):
        link = self._link(pk, request.user); return render(request, self.template_name, {"link": link, "return_url": self._return_url(link)})
    def post(self, request, pk):
        link = self._link(pk, request.user); return_url = self._return_url(link); link.delete(); messages.success(request, "Manual link removed."); return redirect(return_url)
