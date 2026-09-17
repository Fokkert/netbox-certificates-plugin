from .labels import AcronymTableMixin
import django_tables2 as tables
from netbox.tables import PrimaryModelTable, columns
from django.urls import reverse
from django.utils.html import format_html_join
from .permissions import object_allowed
from .finding_display import finding_object_link

from .models_v1 import AlertChannel, AlertEvent, AlertRule, HealthFinding, ObjectLink, Service


class ServiceTable(AcronymTableMixin, PrimaryModelTable):
    actions = columns.ActionsColumn(actions=("edit", "delete"))
    name = tables.Column(linkify=True)
    groups = columns.ManyToManyColumn(linkify_item=True)

    class Meta(PrimaryModelTable.Meta):
        model = Service
        fields = (
            "pk", "id", "name", "status", "service_type", "deployment", "deployment_metadata", "environment",
            "primary_url", "hostname", "port", "sni_name", "criticality",
            "groups", "enabled", "description", "owner", "tags", "last_updated",
        )
        default_columns = (
            "pk", "name", "status", "service_type", "deployment", "environment",
            "hostname", "port", "criticality",
        )


class HealthFindingTable(AcronymTableMixin, PrimaryModelTable):
    actions = columns.ActionsColumn(actions=("edit", "delete"))
    summary = tables.Column(linkify=True)
    affected_object = tables.Column(orderable=False)
    related_object = tables.Column(orderable=False)

    def render_affected_object(self, value):
        request = getattr(self, "request", None) or getattr(self, "context", {}).get("request")
        return finding_object_link(value, request.user) if request else None

    def render_related_object(self, value):
        return self.render_affected_object(value)

    class Meta(PrimaryModelTable.Meta):
        model = HealthFinding
        fields = (
            "pk", "id", "severity", "status", "category", "code", "summary",
            "affected_object", "related_object", "first_detected", "last_detected",
            "resolved_at", "owner", "tags",
        )
        default_columns = (
            "pk", "severity", "status", "category", "summary",
            "affected_object", "related_object", "last_detected",
        )


class ObjectLinkTable(AcronymTableMixin, PrimaryModelTable):
    actions = columns.ActionsColumn(actions=("edit", "delete"))
    source = tables.Column(orderable=False)
    target = tables.Column(orderable=False)

    def render_actions(self, record):
        request = getattr(self, "request", None) or getattr(self, "context", {}).get("request")
        if record.automatic or request is None:
            return ""
        buttons = []
        for action, permission, icon, label in (("edit", "change", "pencil", "Edit link"),
                                                 ("delete", "delete", "trash-can-outline", "Delete link")):
            if object_allowed(request.user, record, permission):
                buttons.append((reverse(f"plugins:netbox_certificates:objectlink_{action}", args=[record.pk]), label, icon))
        return format_html_join(" ", '<a class="btn btn-sm btn-outline-secondary" href="{}" title="{}"><i class="mdi mdi-{}"></i></a>', buttons)

    class Meta(PrimaryModelTable.Meta):
        model = ObjectLink
        fields = (
            "pk", "id", "source", "target", "relationship", "label", "automatic", "enabled",
            "description", "owner", "tags", "last_updated",
        )
        default_columns = ("pk", "source", "target", "relationship", "label", "automatic", "enabled")


class AlertChannelTable(AcronymTableMixin, PrimaryModelTable):
    actions = columns.ActionsColumn(actions=("edit", "delete"))
    name = tables.Column(linkify=True)

    class Meta(PrimaryModelTable.Meta):
        model = AlertChannel
        fields = (
            "pk", "id", "name", "enabled", "channel_type", "webhook_method", "subject_prefix",
            "description", "owner", "tags", "last_updated",
        )
        default_columns = ("pk", "name", "enabled", "channel_type", "subject_prefix")


class AlertRuleTable(AcronymTableMixin, PrimaryModelTable):
    actions = columns.ActionsColumn(actions=("edit", "delete"))
    name = tables.Column(linkify=True)
    channels = columns.ManyToManyColumn(linkify_item=True)
    services = columns.ManyToManyColumn(linkify_item=True)
    groups = columns.ManyToManyColumn(linkify_item=True)

    class Meta(PrimaryModelTable.Meta):
        model = AlertRule
        fields = (
            "pk", "id", "name", "enabled", "channels", "services", "groups",
            "cooldown_minutes", "repeat_minutes", "notify_on_recovery",
            "description", "owner", "tags", "last_updated",
        )
        default_columns = ("pk", "name", "enabled", "channels", "cooldown_minutes", "repeat_minutes")


class AlertEventTable(AcronymTableMixin, PrimaryModelTable):
    actions = columns.ActionsColumn(actions=())
    class Meta(PrimaryModelTable.Meta):
        model = AlertEvent
        fields = (
            "pk", "id", "status", "rule", "channel", "finding", "delivered_at",
            "error", "created", "owner", "tags",
        )
        default_columns = ("pk", "status", "rule", "channel", "finding", "delivered_at", "created")
