import json

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings


class SecretConfigurationError(RuntimeError):
    pass


def _fernet():
    config = getattr(settings, "PLUGINS_CONFIG", {}).get("netbox_certificates", {})
    key = config.get("encryption_key")
    if not key:
        raise SecretConfigurationError("netbox_certificates.encryption_key is not configured.")
    if isinstance(key, str):
        key = key.encode("ascii")
    return Fernet(key)


def encrypt_text(value):
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        value = json.dumps(value, sort_keys=True)
    return _fernet().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_text(value, default=""):
    if not value:
        return default
    try:
        return _fernet().decrypt(value.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, TypeError) as exc:
        raise SecretConfigurationError("Encrypted alert configuration cannot be decrypted.") from exc


def encrypt_json(value):
    return encrypt_text(json.dumps(value or {}, sort_keys=True))


def decrypt_json(value):
    raw = decrypt_text(value, default="{}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SecretConfigurationError("Encrypted alert JSON configuration is invalid.") from exc
    return parsed if isinstance(parsed, dict) else {}
