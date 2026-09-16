from .empty_exports import EmptyListExportMixin
from .labels import display_label
from .finding_display import finding_object_link, finding_data_display
from collections import defaultdict
from functools import partial

from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.core.paginator import Paginator
from django.contrib.contenttypes.models import ContentType
from django.db.models import Count, Q
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse
from django.views import View
from netbox.forms import PrimaryModelFilterSetForm
from netbox.views import generic
from utilities.forms.fields import DynamicModelMultipleChoiceField
from utilities.forms.rendering import FieldSet

from . import views as legacy_views
from .artifact_filtersets_v1 import (
    ArtifactGroupV1FilterSet,
    BundleV1FilterSet,
    CertificateV1FilterSet,
    CSRV1FilterSet,
    PrivateKeyV1FilterSet,
)
from .filtersets_v1 import (
    AlertChannelFilterSet,
    AlertEventFilterSet,
    AlertRuleFilterSet,
    HealthFindingFilterSet,
    ObjectLinkFilterSet,
    ServiceFilterSet,
)
from .forms_v1 import (
    AlertChannelBulkEditForm,
    AlertChannelFilterForm,
    AlertChannelForm,
    AlertEventBulkEditForm,
    AlertEventFilterForm,
    AlertRuleBulkEditForm,
    AlertRuleFilterForm,
    AlertRuleForm,
    HealthFindingBulkEditForm,
    HealthFindingFilterForm,
    ObjectLinkBulkEditForm,
    ObjectLinkFilterForm,
    ObjectLinkForm,
    ServiceBulkEditForm,
    ServiceFilterForm,
    ServiceForm,
)
from .models import ArtifactGroup, Bundle, Certificate, CSR, PrivateKey
from .permissions import action_queryset, object_allowed
from .models_v1 import (
    AlertChannel,
    AlertEvent,
    AlertRule,
    HealthFinding,
    ObjectLink,
    Service,
)
from .tables_v1 import (
    AlertChannelTable,
    AlertEventTable,
    AlertRuleTable,
    HealthFindingTable,
    ObjectLinkTable,
    ServiceTable,
)


FULL_ACTIONS = legacy_views.CertificateListView.actions
NO_RENAME_ACTIONS = tuple(
    action for action in FULL_ACTIONS
    if getattr(action, "__name__", "") != "BulkRename"
)
SYSTEM_ACTIONS = tuple(
    action for action in FULL_ACTIONS
    if getattr(action, "__name__", "") not in {"AddObject", "BulkRename"}
)


def _legacy_filter_form(view_class):
    """Return the existing 0.5 filter form so 1.0 extends rather than replaces it."""

    return getattr(view_class, "filterset_form", None) or PrimaryModelFilterSetForm


_ArtifactGroupLegacyFilterForm = _legacy_filter_form(legacy_views.ArtifactGroupListView)
_CertificateLegacyFilterForm = _legacy_filter_form(legacy_views.CertificateListView)
_PrivateKeyLegacyFilterForm = _legacy_filter_form(legacy_views.PrivateKeyListView)
_CSRLegacyFilterForm = _legacy_filter_form(legacy_views.CSRListView)
_BundleLegacyFilterForm = _legacy_filter_form(legacy_views.BundleListView)


def _extend_fieldsets(base, *names):
    existing = tuple(getattr(base, "fieldsets", ()) or ())
    return existing + (FieldSet(*names, name="Certificate Management"),)


class ArtifactGroupV1FilterForm(_ArtifactGroupLegacyFilterForm):
    model = ArtifactGroup
    service_id = DynamicModelMultipleChoiceField(
        queryset=Service.objects.all(), required=False, label="Service"
    )
    fieldsets = _extend_fieldsets(_ArtifactGroupLegacyFilterForm, "service_id")


class CertificateV1FilterForm(_CertificateLegacyFilterForm):
    model = Certificate
    service_id = DynamicModelMultipleChoiceField(
        queryset=Service.objects.all(), required=False, label="Service"
    )
    fieldsets = _extend_fieldsets(_CertificateLegacyFilterForm, "service_id")


class PrivateKeyV1FilterForm(_PrivateKeyLegacyFilterForm):
    model = PrivateKey
    service_id = DynamicModelMultipleChoiceField(
        queryset=Service.objects.all(), required=False, label="Service"
    )
    fieldsets = _extend_fieldsets(_PrivateKeyLegacyFilterForm, "service_id")


class CSRV1FilterForm(_CSRLegacyFilterForm):
    model = CSR
    service_id = DynamicModelMultipleChoiceField(
        queryset=Service.objects.all(), required=False, label="Service"
    )
    fieldsets = _extend_fieldsets(_CSRLegacyFilterForm, "service_id")


class BundleV1FilterForm(_BundleLegacyFilterForm):
    model = Bundle
    service_id = DynamicModelMultipleChoiceField(
        queryset=Service.objects.all(), required=False, label="Service"
    )
    fieldsets = _extend_fieldsets(_BundleLegacyFilterForm, "service_id")


class CertificateListView(legacy_views.CertificateListView):
    filterset = CertificateV1FilterSet
    filterset_form = CertificateV1FilterForm


class PrivateKeyListView(legacy_views.PrivateKeyListView):
    filterset = PrivateKeyV1FilterSet
    filterset_form = PrivateKeyV1FilterForm


class CSRListView(legacy_views.CSRListView):
    filterset = CSRV1FilterSet
    filterset_form = CSRV1FilterForm


class BundleListView(legacy_views.BundleListView):
    filterset = BundleV1FilterSet
    filterset_form = BundleV1FilterForm


class CryptographicVaultView(LoginRequiredMixin, View):
    template_name = "netbox_certificates/vault.html"

    @staticmethod
    def _visible(queryset, user):
        return queryset.restrict(user, "view") if hasattr(queryset, "restrict") else queryset

    def get(self, request):
        certificates = self._visible(Certificate.objects.all(), request.user)
        private_keys = self._visible(PrivateKey.objects.all(), request.user)
        csrs = self._visible(CSR.objects.all(), request.user)
        bundles = self._visible(Bundle.objects.all(), request.user)
        services = self._visible(Service.objects.all(), request.user)
        health_active = self._visible(HealthFinding.objects.filter(status__in=("active", "acknowledged")), request.user)

        cards = (
            ("Certificates", certificates.count(), reverse("plugins:netbox_certificates:certificate_list")),
            ("Certificate Authorities", certificates.filter(is_ca=True).count(), reverse("plugins:netbox_certificates:certificate_list") + "?is_ca=true"),
            ("Private Keys", private_keys.count(), reverse("plugins:netbox_certificates:privatekey_list")),
            ("CSRs", csrs.count(), reverse("plugins:netbox_certificates:csr_list")),
            ("Bundles", bundles.count(), reverse("plugins:netbox_certificates:bundle_list")),
            ("Services", services.count(), reverse("plugins:netbox_certificates:service_list")),
            ("Active Health Findings", health_active.count(), reverse("plugins:netbox_certificates:health")),
            ("Critical Findings", health_active.filter(severity="critical").count(), reverse("plugins:netbox_certificates:health") + "?severity=critical"),
        )
        return render(
            request,
            self.template_name,
            {
                "vault_cards": cards,
                "vault_health_categories": list(
                    health_active.values("category").annotate(total=Count("pk")).order_by("-total", "category")
                ),
                "unassigned_certificates": certificates.filter(services__isnull=True).distinct().count(),
                "unassigned_private_keys": private_keys.filter(services__isnull=True).distinct().count(),
                "unassigned_csrs": csrs.filter(services__isnull=True).distinct().count(),
                "unassigned_bundles": bundles.filter(services__isnull=True).distinct().count(),
            },
        )


class ArtifactGroupTreeListView(LoginRequiredMixin, View):
    queryset = ArtifactGroup.objects.all()
    filterset = ArtifactGroupV1FilterSet
    filterset_form = ArtifactGroupV1FilterForm
    template_name = "netbox_certificates/artifactgroup_tree_list.html"

    def get(self, request):
        if not request.user.has_perm("netbox_certificates.view_artifactgroup"):
            raise PermissionDenied
        return render(request, self.template_name, self.get_extra_context(request))

    def get_extra_context(self, request):
        context = {}

        visible = self.queryset.restrict(request.user, "view") if hasattr(self.queryset, "restrict") else self.queryset
        tree_filter = ArtifactGroupV1FilterSet(request.GET, queryset=visible, request=request)
        visible = tree_filter.qs if tree_filter.is_valid() else visible.none()
        groups = list(visible.select_related("parent").distinct().order_by("name"))
        children = defaultdict(list)
        by_id = {group.pk: group for group in groups}
        for group in groups:
            children[group.parent_id].append(group)

        # One query per object type; list only members the user can view.
        counts, members = {}, defaultdict(list)
        for name, model in (("certificates", Certificate), ("private_keys", PrivateKey),
                            ("csrs", CSR), ("bundles", Bundle), ("services", Service)):
            counts[name] = defaultdict(int)
            rows = action_queryset(model, request.user, "view").filter(groups__in=by_id).values("pk", "name", "groups").distinct().order_by("name")
            for row in rows:
                obj = model(pk=row["pk"], name=row["name"])
                counts[name][row["groups"]] += 1
                members[row["groups"]].append({"name": obj.name, "url": obj.get_absolute_url(),
                                              "type": display_label(str(model._meta.verbose_name).title())})

        def relation_count(group, name):
            return counts[name].get(group.pk, 0)

        def node(group):
            artifact_count = sum(
                relation_count(group, name)
                for name in ("certificates", "private_keys", "csrs", "bundles")
            )
            return {
                "id": group.pk,
                "name": str(group),
                "url": group.get_absolute_url(),
                "parent_id": group.parent_id,
                "children": [node(child) for child in sorted(children[group.pk], key=lambda item: str(item).lower())],
                "service_count": relation_count(group, "services"),
                "artifact_count": artifact_count,
                "members": members[group.pk],
            }

        roots = [group for group in groups if not group.parent_id or group.parent_id not in by_id]
        context["filter_errors"] = tree_filter.errors
        context["group_tree"] = [node(group) for group in sorted(roots, key=lambda item: str(item).lower())]
        return context


class V1ObjectView(generic.ObjectView):
    template_name = "netbox_certificates/v1_object.html"
    detail_fields = ()

    def get_extra_context(self, request, instance):
        rows = []
        for field_name in self.detail_fields:
            try:
                field = instance._meta.get_field(field_name)
                label = display_label(str(field.verbose_name).title())
            except Exception:
                label = display_label(field_name.replace("_", " ").title())
            value = getattr(instance, field_name, None)
            if hasattr(value, "all"):
                items = value.all()
                if hasattr(items, "restrict"):
                    items = items.restrict(request.user, "view")
                value = ", ".join(str(item) for item in items)
            elif hasattr(value, "_meta") and not object_allowed(request.user, value):
                value = None
            rows.append((label, value))
        return {"detail_rows": rows}


class ServiceListView(EmptyListExportMixin, generic.ObjectListView):
    queryset = Service.objects.all()
    table = ServiceTable
    filterset = ServiceFilterSet
    filterset_form = ServiceFilterForm
    actions = FULL_ACTIONS
    template_name = "netbox_certificates/service_list.html"


class ServiceView(V1ObjectView):
    queryset = Service.objects.all()
    detail_fields = (
        "name", "status", "service_type", "other_type", "deployment", "deployment_metadata", "environment",
        "protocol", "primary_url", "additional_urls", "hostname", "port", "sni_name",
        "criticality", "external_reference", "contact", "enabled", "groups",
        "certificates", "private_keys", "csrs", "bundles", "owner", "description", "comments",
    )

    def get_extra_context(self, request, instance):
        context = super().get_extra_context(request, instance)
        service_type = ContentType.objects.get_for_model(instance, for_concrete_model=False)
        context["object_links"] = ObjectLink.objects.filter(
            source_type=service_type,
            source_object_id=instance.pk,
            enabled=True,
        ).select_related("target_type")
        return context


class ServiceEditView(generic.ObjectEditView):
    queryset = Service.objects.all()
    form = ServiceForm
    template_name = "netbox_certificates/service_edit.html"


class ServiceDeleteView(generic.ObjectDeleteView):
    queryset = Service.objects.all()


class ServiceBulkEditView(generic.BulkEditView):
    queryset = Service.objects.all()
    filterset = ServiceFilterSet
    table = ServiceTable
    form = ServiceBulkEditForm


class ServiceBulkRenameView(generic.BulkRenameView):
    queryset = Service.objects.all()


class ServiceBulkDeleteView(generic.BulkDeleteView):
    queryset = Service.objects.all()
    filterset = ServiceFilterSet
    table = ServiceTable


class HealthFindingListView(LoginRequiredMixin, View):
    queryset = HealthFinding.objects.all()
    table = HealthFindingTable
    filterset = HealthFindingFilterSet
    filterset_form = HealthFindingFilterForm
    actions = SYSTEM_ACTIONS
    template_name = "netbox_certificates/healthfinding_list.html"

    def get(self, request):
        if not (request.user.has_perm("netbox_certificates.view_healthfinding") or
                request.user.has_perm("netbox_certificates.view_certificate")):
            raise PermissionDenied
        visible = action_queryset(HealthFinding, request.user, "view")
        filtered = HealthFindingFilterSet(request.GET, queryset=visible, request=request)
        context = self.get_extra_context(request)
        context["filter_form"] = HealthFindingFilterForm(request.GET or None)
        context["findings"] = Paginator(filtered.qs if filtered.is_valid() else visible.none(), 50).get_page(request.GET.get("page"))
        for finding in context["findings"]:
            finding.affected_link = finding_object_link(finding.affected_object, request.user)
            finding.related_link = finding_object_link(finding.related_object, request.user)
            finding.details_display = finding_data_display(finding.details)
            finding.evidence_display = finding_data_display(finding.evidence)
        query = request.GET.copy()
        query.pop("page", None)
        context["filter_query"] = query.urlencode()
        from .services.expiry import expiry_state
        certificates = action_queryset(Certificate, request.user, "view").order_by("valid_to")
        counts = dict.fromkeys(("healthy", "warning", "critical", "expired", "unknown"), 0)
        upcoming = []
        for cert in certificates.iterator():
            state = expiry_state(cert)
            counts[state["level"]] += 1
            if state["level"] in {"warning", "critical", "expired"} and len(upcoming) < 50:
                upcoming.append((cert, state))
        context.update(counts=counts, upcoming=upcoming)
        return render(request, self.template_name, context)

    def get_extra_context(self, request):
        active = action_queryset(HealthFinding, request.user, "view").filter(status__in=("active", "acknowledged"))
        if hasattr(active, "restrict"):
            active = active.restrict(request.user, "view")
        return {
            "health_counts": {
                "critical": active.filter(severity="critical").count(),
                "high": active.filter(severity="high").count(),
                "medium": active.filter(severity="medium").count(),
                "warning": active.filter(severity="warning").count(),
                "info": active.filter(severity="info").count(),
                "total": active.count(),
            },
            "health_categories": list(
                active.values("category").annotate(total=Count("pk")).order_by("-total", "category")
            ),
        }


class HealthFindingView(V1ObjectView):
    queryset = HealthFinding.objects.all()
    actions = tuple(action for action in generic.ObjectView.actions if action.__name__ != "CloneObject")
    detail_fields = (
        "severity", "status", "category", "code", "summary", "affected_object",
        "related_object", "details", "evidence", "fingerprint",
        "first_detected", "last_detected", "resolved_at", "owner", "description", "comments",
    )

    def get_extra_context(self, request, instance):
        context = super().get_extra_context(request, instance)
        replacements = {
            "affected_object": finding_object_link(instance.affected_object, request.user),
            "related_object": finding_object_link(instance.related_object, request.user),
            "details": finding_data_display(instance.details),
            "evidence": finding_data_display(instance.evidence),
        }
        context["detail_rows"] = [
            (label, replacements.get(field, value))
            for field, (label, value) in zip(self.detail_fields, context["detail_rows"])
        ]
        return context


class FindingWorkflowPermissionMixin:
    def dispatch(self, request, *args, **kwargs):
        action = {"acknowledged": "acknowledge", "ignored": "ignore", "resolved": "resolve"}.get(request.POST.get("status"))
        if request.method == "POST" and action:
            allowed = action_queryset(HealthFinding, request.user, action)
            self.queryset = self.queryset.filter(Q(status=request.POST["status"]) | Q(pk__in=allowed))
        return super().dispatch(request, *args, **kwargs)


class HealthFindingEditView(FindingWorkflowPermissionMixin, generic.ObjectEditView):
    queryset = HealthFinding.objects.all()
    from .forms_v1 import HealthFindingForm as form


class HealthFindingDeleteView(generic.ObjectDeleteView):
    queryset = HealthFinding.objects.all()


class HealthFindingBulkEditView(FindingWorkflowPermissionMixin, generic.BulkEditView):
    queryset = HealthFinding.objects.all()
    filterset = HealthFindingFilterSet
    table = HealthFindingTable
    form = HealthFindingBulkEditForm


class HealthFindingBulkDeleteView(generic.BulkDeleteView):
    queryset = HealthFinding.objects.all()
    filterset = HealthFindingFilterSet
    table = HealthFindingTable


class HealthRefreshView(LoginRequiredMixin, View):
    def post(self, request):
        if not (
            request.user.is_superuser
            or request.user.has_perm("netbox_certificates.run_healthscan_healthfinding")
        ):
            raise Http404
        from .services.health_v1 import refresh_health_findings
        result = refresh_health_findings()
        messages.success(request, f"Health scan complete: {result['active']} active findings.")
        return redirect("plugins:netbox_certificates:health")


class ObjectLinkListView(EmptyListExportMixin, generic.ObjectListView):
    queryset = ObjectLink.objects.all()
    table = ObjectLinkTable
    filterset = ObjectLinkFilterSet
    filterset_form = ObjectLinkFilterForm
    actions = NO_RENAME_ACTIONS
    template_name = "netbox_certificates/objectlink_list.html"


class ObjectLinkView(V1ObjectView):
    queryset = ObjectLink.objects.all()
    detail_fields = (
        "source", "target", "relationship", "label", "enabled", "owner", "description", "comments",
    )


class ObjectLinkEditView(generic.ObjectEditView):
    queryset = ObjectLink.objects.filter(automatic=False)
    form = ObjectLinkForm

    def dispatch(self, request, *args, **kwargs):
        self.form = partial(ObjectLinkForm, user=request.user)
        return super().dispatch(request, *args, **kwargs)


class ObjectLinkDeleteView(generic.ObjectDeleteView):
    queryset = ObjectLink.objects.filter(automatic=False)


class ObjectLinkBulkEditView(generic.BulkEditView):
    queryset = ObjectLink.objects.filter(automatic=False)
    filterset = ObjectLinkFilterSet
    table = ObjectLinkTable
    form = ObjectLinkBulkEditForm


class ObjectLinkBulkDeleteView(generic.BulkDeleteView):
    queryset = ObjectLink.objects.filter(automatic=False)
    filterset = ObjectLinkFilterSet
    table = ObjectLinkTable


class AlertRuleListView(EmptyListExportMixin, generic.ObjectListView):
    queryset = AlertRule.objects.all()
    table = AlertRuleTable
    filterset = AlertRuleFilterSet
    filterset_form = AlertRuleFilterForm
    actions = FULL_ACTIONS
    template_name = "netbox_certificates/alertrule_list.html"


class AlertRuleView(V1ObjectView):
    queryset = AlertRule.objects.all()
    detail_fields = (
        "name", "enabled", "finding_codes", "categories", "severities", "statuses",
        "object_types", "tag_names", "owner_ids",
        "cooldown_minutes", "repeat_minutes", "notify_on_recovery", "channels",
        "services", "groups", "owner", "description", "comments",
    )

    def get_extra_context(self, request, instance):
        context = super().get_extra_context(request, instance)
        context["test_action_name"] = "alertrule_test"
        return context


class AlertRuleEditView(generic.ObjectEditView):
    queryset = AlertRule.objects.all()
    form = AlertRuleForm


class AlertRuleDeleteView(generic.ObjectDeleteView):
    queryset = AlertRule.objects.all()


class AlertRuleBulkEditView(generic.BulkEditView):
    queryset = AlertRule.objects.all()
    filterset = AlertRuleFilterSet
    table = AlertRuleTable
    form = AlertRuleBulkEditForm


class AlertRuleBulkRenameView(generic.BulkRenameView):
    queryset = AlertRule.objects.all()


class AlertRuleBulkDeleteView(generic.BulkDeleteView):
    queryset = AlertRule.objects.all()
    filterset = AlertRuleFilterSet
    table = AlertRuleTable


class AlertChannelListView(EmptyListExportMixin, generic.ObjectListView):
    queryset = AlertChannel.objects.all()
    table = AlertChannelTable
    filterset = AlertChannelFilterSet
    filterset_form = AlertChannelFilterForm
    actions = FULL_ACTIONS
    template_name = "netbox_certificates/alertchannel_list.html"


class AlertChannelView(V1ObjectView):
    queryset = AlertChannel.objects.all()
    detail_fields = (
        "name", "enabled", "channel_type", "recipients",
        "smtp_host", "smtp_port", "smtp_username", "smtp_use_tls", "smtp_use_ssl",
        "from_email", "subject_prefix", "owner", "description", "comments",
    )

    def get_extra_context(self, request, instance):
        context = super().get_extra_context(request, instance)
        context["test_action_name"] = "alertchannel_test"
        return context


class AlertChannelEditView(generic.ObjectEditView):
    queryset = AlertChannel.objects.all()
    form = AlertChannelForm


class AlertChannelDeleteView(generic.ObjectDeleteView):
    queryset = AlertChannel.objects.all()


class AlertChannelBulkEditView(generic.BulkEditView):
    queryset = AlertChannel.objects.all()
    filterset = AlertChannelFilterSet
    table = AlertChannelTable
    form = AlertChannelBulkEditForm


class AlertChannelBulkRenameView(generic.BulkRenameView):
    queryset = AlertChannel.objects.all()


class AlertChannelBulkDeleteView(generic.BulkDeleteView):
    queryset = AlertChannel.objects.all()
    filterset = AlertChannelFilterSet
    table = AlertChannelTable


class AlertEventListView(EmptyListExportMixin, generic.ObjectListView):
    queryset = AlertEvent.objects.all()
    table = AlertEventTable
    filterset = AlertEventFilterSet
    filterset_form = AlertEventFilterForm
    actions = SYSTEM_ACTIONS
    template_name = "netbox_certificates/alertevent_list.html"


class AlertEventView(V1ObjectView):
    queryset = AlertEvent.objects.all()
    actions = ()
    detail_fields = (
        "status", "rule", "channel", "finding", "delivered_at", "error",
        "payload_summary", "owner", "description", "comments",
    )


class AlertEventBulkEditView(generic.BulkEditView):
    queryset = AlertEvent.objects.all()
    filterset = AlertEventFilterSet
    table = AlertEventTable
    form = AlertEventBulkEditForm


class AlertEventBulkDeleteView(generic.BulkDeleteView):
    queryset = AlertEvent.objects.all()
    filterset = AlertEventFilterSet
    table = AlertEventTable


class AlertChannelTestView(LoginRequiredMixin, View):
    def post(self, request, pk):
        channel = action_queryset(AlertChannel, request.user, "test").filter(pk=pk).first()
        if channel is None and not request.user.is_superuser:
            raise Http404
        if channel is None:
            channel = AlertChannel.objects.filter(pk=pk).first()
        if channel is None:
            raise Http404
        from .services.alerts_v1 import send_test_channel
        try:
            send_test_channel(channel)
        except Exception as exc:
            messages.error(request, f"Alert channel test failed ({type(exc).__name__}). Check destination and TLS settings.")
        else:
            messages.success(request, "Alert channel test delivered successfully.")
        if request.POST.get("return_to_settings") and request.user.is_superuser:
            return redirect("plugins:netbox_certificates:alert_settings")
        return redirect(channel.get_absolute_url())


class AlertRuleTestView(LoginRequiredMixin, View):
    def post(self, request, pk):
        rule = action_queryset(AlertRule, request.user, "test").filter(pk=pk).first()
        if rule is None and not request.user.is_superuser:
            raise Http404
        if rule is None:
            rule = AlertRule.objects.filter(pk=pk).first()
        if rule is None:
            raise Http404
        from .services.alerts_v1 import dispatch_alerts
        result = dispatch_alerts(rule_ids=[rule.pk], bypass_cooldown=True)
        messages.success(
            request,
            f"Rule test finished: {result['delivered']} delivered, {result['failed']} failed, {result['skipped']} skipped.",
        )
        return redirect(rule.get_absolute_url())
