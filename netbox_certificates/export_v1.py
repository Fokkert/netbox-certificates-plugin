import hashlib
import json
import tempfile
import zipfile
from datetime import datetime, timezone

from django.core.serializers.json import DjangoJSONEncoder
from django.http import FileResponse, Http404, QueryDict
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin

from .artifact_filtersets_v1 import ArtifactGroupV1FilterSet
from .filtersets_v1 import (
    AlertChannelFilterSet,
    AlertEventFilterSet,
    AlertRuleFilterSet,
    CertificatePolicyFilterSet,
    HealthFindingFilterSet,
    ObjectLinkFilterSet,
    ServiceFilterSet,
)
from .models import ArtifactGroup
from .models_v1 import AlertChannel, AlertEvent, AlertRule, CertificatePolicy, HealthFinding, ObjectLink, Service
from .permissions import action_queryset


CONFIG = {
    "artifactgroup": (ArtifactGroup, ArtifactGroupV1FilterSet, "view", "groups-export.zip"),
    "service": (Service, ServiceFilterSet, "archive_export", "services-export.zip"),
    "certificatepolicy": (CertificatePolicy, CertificatePolicyFilterSet, "archive_export", "certificate-policies-export.zip"),
    "healthfinding": (HealthFinding, HealthFindingFilterSet, "archive_export", "health-findings-export.zip"),
    "objectlink": (ObjectLink, ObjectLinkFilterSet, "archive_export", "object-links-export.zip"),
    "alertchannel": (AlertChannel, AlertChannelFilterSet, "archive_export", "alert-channels-export.zip"),
    "alertrule": (AlertRule, AlertRuleFilterSet, "archive_export", "alert-rules-export.zip"),
    "alertevent": (AlertEvent, AlertEventFilterSet, "archive_export", "alert-events-export.zip"),
}


def _filtered_data(filterset_class, request):
    allowed = set(filterset_class.base_filters.keys()) | {"filter", "filter_id"}
    data = QueryDict("", mutable=True)
    for key in allowed:
        for value in request.GET.getlist(key):
            data.appendlist(key, value)
    return data


def _safe_value(obj, field):
    value = getattr(obj, field.name)
    if field.many_to_many:
        return list(value.values_list("pk", flat=True))
    if field.many_to_one:
        return getattr(obj, field.attname)
    return value


def serialize_object(obj):
    values = {}
    sensitive_names = {"smtp_password_encrypted", "webhook_url_encrypted", "webhook_headers_encrypted", "encrypted_material", "material"}
    for field in obj._meta.get_fields():
        if not getattr(field, "concrete", False) or getattr(field, "auto_created", False):
            continue
        if field.name in sensitive_names:
            continue
        try:
            values[field.name] = _safe_value(obj, field)
        except Exception:
            continue

    # Explicitly expose relationship identifiers without material or alert secrets.
    if isinstance(obj, Service):
        values["group_ids"] = list(obj.groups.values_list("pk", flat=True))
        values["certificate_ids"] = list(obj.certificates.values_list("pk", flat=True))
        values["private_key_ids"] = list(obj.private_keys.values_list("pk", flat=True))
        values["csr_ids"] = list(obj.csrs.values_list("pk", flat=True))
        values["bundle_ids"] = list(obj.bundles.values_list("pk", flat=True))
    if isinstance(obj, AlertRule):
        values["channel_ids"] = list(obj.channels.values_list("pk", flat=True))
        values["service_ids"] = list(obj.services.values_list("pk", flat=True))
        values["policy_ids"] = list(obj.policies.values_list("pk", flat=True))
        values["group_ids"] = list(obj.groups.values_list("pk", flat=True))

    return {
        "type": obj._meta.label_lower,
        "id": obj.pk,
        "display": str(obj),
        "attributes": values,
    }


def _write(archive, name, data):
    info = zipfile.ZipInfo(name)
    info.create_system = 3
    info.external_attr = 0o600 << 16
    archive.writestr(info, data, compress_type=zipfile.ZIP_DEFLATED)
    return hashlib.sha256(data).hexdigest()


class MetadataArchiveExportView(LoginRequiredMixin, View):
    spool_limit = 8 * 1024 * 1024

    def get(self, request, kind):
        try:
            model, filterset_class, action, filename = CONFIG[kind]
        except KeyError:
            raise Http404("Unknown archive export type.")

        queryset = action_queryset(model, request.user, action)
        filter_data = _filtered_data(filterset_class, request)
        filterset = filterset_class(filter_data or None, queryset=queryset)
        if not filterset.is_valid():
            raise Http404("The current object filter is invalid.")
        objects = list(filterset.qs.order_by("pk"))
        if not objects:
            raise Http404("No objects are available for export with your permissions and current filters.")

        records = [serialize_object(obj) for obj in objects]
        data = json.dumps(records, indent=2, sort_keys=True, cls=DjangoJSONEncoder).encode("utf-8")
        manifest = {
            "format": "netbox-certificates-export-manifest",
            "manifest_version": 1,
            "plugin_version": "1.0.1",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "object_kind": kind,
            "count": len(records),
            "filters": {key: filter_data.getlist(key) for key in filter_data.keys()},
            "files": [{"path": "objects.json", "sha256": hashlib.sha256(data).hexdigest()}],
            "sensitive": False,
        }

        output = tempfile.SpooledTemporaryFile(max_size=self.spool_limit, mode="w+b")
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as archive:
            _write(archive, "objects.json", data)
            _write(archive, "manifest.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8"))
        output.seek(0)
        response = FileResponse(output, as_attachment=True, filename=filename, content_type="application/zip")
        response["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
        response["Pragma"] = "no-cache"
        response["X-Content-Type-Options"] = "nosniff"
        return response
