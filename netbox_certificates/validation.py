"""Shared validation used by forms, models, and API operations."""
import ipaddress
import re
from urllib.parse import urlsplit

from django.core.exceptions import ValidationError
from django.core.validators import URLValidator
from django import forms


class OptionalObjectJSONField(forms.JSONField):
    """Blank preserves a stored value; an explicit {} clears it."""
    empty_values = (None, "")

    def validate(self, value):
        super().validate(value)
        if value is not None and not isinstance(value, dict):
            raise ValidationError("Enter a JSON object.")


def validate_hostname(value, *, wildcard=False):
    if not value:
        return
    try:
        ipaddress.ip_address(value)
        return
    except ValueError:
        pass
    name = value[2:] if wildcard and value.startswith("*.") else value
    try:
        name = name.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValidationError("Enter a valid hostname or IP address.") from exc
    if len(name) > 253 or not all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in name.split(".")):
        raise ValidationError("Enter a valid hostname or IP address.")


def validate_endpoint_url(value, *, http_only=False):
    if not value:
        return
    URLValidator(schemes=["https", "http"] if http_only else ["https", "http", "ftp", "ftps"])(value)
    try:
        parsed = urlsplit(value)
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError
        if http_only and (parsed.username is not None or parsed.password is not None):
            raise ValueError
    except ValueError as exc:
        raise ValidationError("Enter a valid URL with a port from 1 to 65535 and no embedded webhook credentials.") from exc


def validate_headers(value):
    if not isinstance(value, dict):
        raise ValidationError("Enter a JSON object of HTTP header names and string values.")
    for key, item in value.items():
        if not isinstance(key, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key):
            raise ValidationError("Invalid HTTP header name.")
        if not isinstance(item, str) or any(ord(char) < 32 or ord(char) == 127 for char in item):
            raise ValidationError("HTTP header values must be strings without control characters.")
        try:
            item.encode("latin-1")
        except UnicodeEncodeError as exc:
            raise ValidationError("HTTP header values must use Latin-1 characters.") from exc


def validate_port(value):
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValidationError("Port must be an integer between 1 and 65535.")
