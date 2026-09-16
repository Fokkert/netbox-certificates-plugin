from .empty_exports import empty_export_response
import hashlib
import json
import tempfile
import zipfile
from datetime import datetime, timezone

from django.core.serializers.json import DjangoJSONEncoder
from django.http import FileResponse, Http404, QueryDict, JsonResponse
from django.views import View
from django.contrib.auth.mixins import LoginRequiredMixin

from .artifact_filtersets_v1 import ArtifactGroupV1FilterSet
from .filtersets_v1 import (
    AlertChannelFilterSet,
    AlertEventFilterSet,
    AlertRuleFilterSet,
    HealthFindingFilterSet,
    ObjectLinkFilterSet,
    ServiceFilterSet,
)
from .models import ArtifactGroup
from .models_v1 import AlertChannel, AlertEvent, AlertRule, HealthFinding, ObjectLink, Service
from .permissions import action_queryset, require_action_permission, object_allowed


CONFIG = {
    "artifactgroup": (ArtifactGroup, ArtifactGroupV1FilterSet, "archive_export", "groups-export.zip"),
    "service": (Service, ServiceFilterSet, "archive_export", "services-export.zip"),
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


def _visible_ids(manager, user):
    queryset = manager.all()
    if user is not None and hasattr(queryset, "restrict"):
        queryset = queryset.restrict(user, "view")
    return list(queryset.values_list("pk", flat=True))


def _safe_value(obj, field, user=None):
    value = getattr(obj, field.name)
    if field.many_to_many:
        return _visible_ids(value, user)
    if field.many_to_one:
        return getattr(obj, field.attname) if user is None or object_allowed(user, value) else None
    return value


def serialize_object(obj, user=None):
    values = {}
    sensitive_names = {"smtp_password_encrypted", "webhook_url_encrypted", "webhook_headers_encrypted", "encrypted_material", "material", "policy"}
    for field in obj._meta.get_fields():
        if not getattr(field, "concrete", False) or getattr(field, "auto_created", False):
            continue
        if field.name in sensitive_names:
            continue
        try:
            values[field.name] = _safe_value(obj, field, user)
        except Exception:
            continue

    # Explicitly expose relationship identifiers without material or alert secrets.
    if isinstance(obj, Service):
        values["group_ids"] = _visible_ids(obj.groups, user)
        values["certificate_ids"] = _visible_ids(obj.certificates, user)
        values["private_key_ids"] = _visible_ids(obj.private_keys, user)
        values["csr_ids"] = _visible_ids(obj.csrs, user)
        values["bundle_ids"] = _visible_ids(obj.bundles, user)
    if isinstance(obj, AlertRule):
        values["channel_ids"] = _visible_ids(obj.channels, user)
        values["service_ids"] = _visible_ids(obj.services, user)
        values["group_ids"] = _visible_ids(obj.groups, user)

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

        require_action_permission(model, request.user, action)
        queryset = action_queryset(model, request.user, action)
        filter_data = _filtered_data(filterset_class, request)
        filterset = filterset_class(filter_data, queryset=queryset, request=request)
        if not filterset.is_valid():
            return JsonResponse({"detail": "Invalid export filters.", "errors": filterset.errors.get_json_data()}, status=400)
        objects = list(filterset.qs.order_by("pk"))
        if not objects:
            return empty_export_response(request)
        records = [serialize_object(obj, request.user) for obj in objects]
        data = json.dumps(records, indent=2, sort_keys=True, cls=DjangoJSONEncoder).encode("utf-8")
        manifest = {
            "format": "netbox-certificates-export-manifest",
            "manifest_version": 1,
            "plugin_version": "1.2.0",
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
