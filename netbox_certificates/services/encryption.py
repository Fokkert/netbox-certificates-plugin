from cryptography.fernet import Fernet, InvalidToken
from netbox.plugins import get_plugin_config


class PrivateKeyEncryptionError(ValueError):
    pass


def _fernet():
    key = get_plugin_config("netbox_certificates", "encryption_key")
    if isinstance(key, str):
        key = key.encode("ascii")
    try:
        return Fernet(key)
    except Exception as exc:
        raise PrivateKeyEncryptionError(
            "PLUGINS_CONFIG['netbox_certificates']['encryption_key'] is not a valid Fernet key."
        ) from exc


def encrypt_private_key(data: bytes) -> bytes:
    return _fernet().encrypt(data)


def decrypt_private_key(token: bytes) -> bytes:
    try:
        return _fernet().decrypt(bytes(token))
    except InvalidToken as exc:
        raise PrivateKeyEncryptionError(
            "Unable to decrypt private key. The plugin encryption key may have changed."
        ) from exc


def encrypt_secret(value: str) -> bytes:
    if not value:
        return b""
    return _fernet().encrypt(value.encode("utf-8"))


def decrypt_secret(token) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(bytes(token)).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError) as exc:
        raise PrivateKeyEncryptionError(
            "Unable to decrypt a plugin secret. The plugin encryption key may have changed."
        ) from exc
