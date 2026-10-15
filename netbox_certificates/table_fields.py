"""Optional inventory columns, excluding secrets and internal storage fields."""
import django_tables2 as tables
from django.db import models
from django.utils.html import format_html, format_html_join
from netbox.tables import columns


SENSITIVE_FIELDS = {
    "encrypted_material", "encrypted_archive", "smtp_password_encrypted",
    "webhook_url_encrypted", "webhook_headers_encrypted", "webhook_bearer_token_encrypted",
}


class PublicMaterialColumn(tables.Column):
    def render(self, value):
        return format_html('<details><summary>View PEM</summary><pre>{}</pre></details>', value)


class VisibleRelationshipColumn(tables.Column):
    def __init__(self, **kwargs):
        super().__init__(empty_values=(), orderable=False, **kwargs)

    def render(self, record, table, bound_column):
        value = getattr(record, bound_column.name, None)
        request = getattr(table, "request", None) or getattr(table, "context", {}).get("request")
        if value is None or request is None:
            return "—"
        if hasattr(value, "all"):
            queryset = value.all()
            objects = queryset.restrict(request.user, "view") if hasattr(queryset, "restrict") else queryset.none()
        else:
            queryset = value.__class__.objects.all()
            objects = [value] if hasattr(queryset, "restrict") and queryset.restrict(request.user, "view").filter(pk=value.pk).exists() else []
        return format_html_join(", ", '<a href="{}">{}</a>',
                                ((obj.get_absolute_url(), str(obj)) for obj in objects)) or "—"


def complete_columns(table):
    """Expose safe model fields as optional columns without changing defaults."""
    for field in table._meta.model._meta.get_fields():
        name = field.name
        if name in SENSITIVE_FIELDS or name.startswith("_") or isinstance(field, models.BinaryField):
            continue
        if name in table.base_columns:
            if isinstance(table.base_columns[name], columns.ManyToManyColumn) and name != "tags":
                table.base_columns[name] = VisibleRelationshipColumn(verbose_name=table.base_columns[name].verbose_name)
            continue
        if field.is_relation:
            related = field.related_model
            if related is None or getattr(related, "_netbox_private", False):
                continue
            # Generic audit relations are not inventory fields.
            if not (field.concrete or field.many_to_many or field.one_to_many):
                continue
            if hasattr(related, "get_absolute_url"):
                column = VisibleRelationshipColumn(verbose_name=name.replace("_", " ").capitalize())
            elif field.concrete and not field.many_to_many:
                column = tables.Column(verbose_name=field.verbose_name)
            else:
                continue
        elif name == "material":
            column = PublicMaterialColumn(verbose_name=field.verbose_name, orderable=False)
        elif isinstance(field, models.JSONField):
            column = tables.JSONColumn(verbose_name=field.verbose_name, orderable=False)
        elif field.choices:
            column = columns.ChoiceFieldColumn(verbose_name=field.verbose_name)
        elif isinstance(field, models.DateTimeField):
            column = columns.DateTimeColumn(verbose_name=field.verbose_name)
        elif isinstance(field, models.BooleanField):
            column = tables.BooleanColumn(verbose_name=field.verbose_name)
        else:
            column = tables.Column(verbose_name=field.verbose_name)
        table.base_columns[name] = column
    table._meta.fields = tuple(dict.fromkeys((*table._meta.fields, *table.base_columns)))
    return table
