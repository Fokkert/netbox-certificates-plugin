"""Permission-aware links and escaped, readable health evidence."""
import json

from django.utils.html import format_html, format_html_join

from .labels import display_label
from .permissions import object_allowed


def finding_object_link(obj, user):
    if obj is None or not object_allowed(user, obj):
        return None
    if callable(getattr(obj, "get_absolute_url", None)):
        return format_html('<a href="{}">{}</a>', obj.get_absolute_url(), obj)
    return str(obj)


def finding_data_display(value):
    if not value:
        return None
    if isinstance(value, dict):
        return format_html_join("", '<div><strong>{}:</strong> {}</div>', (
            (display_label(str(key).replace("_", " ").capitalize()),
             json.dumps(item, ensure_ascii=False, default=str) if isinstance(item, (dict, list)) else str(item))
            for key, item in value.items()
        ))
    return str(value)
