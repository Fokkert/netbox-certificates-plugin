from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from .encryption import decrypt_private_key


class PFXExportError(ValueError):
    pass


def build_pfx(bundle, password: str, chain_certificates=None) -> bytes:
    if not password:
        raise PFXExportError("A non-empty password is required for PFX export.")
    if bundle.certificate is None or bundle.private_key is None:
        raise PFXExportError("PFX export requires both a certificate and a private key.")
    try:
        cert = x509.load_pem_x509_certificate(bundle.certificate.material.encode("ascii"))
        key = serialization.load_pem_private_key(decrypt_private_key(bundle.private_key.encrypted_material), password=None)
    except Exception as exc:
        raise PFXExportError(f"Unable to load bundle certificate/private key: {exc}") from exc
    cert_pub = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    key_pub = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    if cert_pub != key_pub:
        raise PFXExportError("The bundle certificate and private key do not match.")
    cas = []
    for obj in chain_certificates or []:
        try:
            cas.append(x509.load_pem_x509_certificate(obj.material.encode("ascii")))
        except Exception as exc:
            raise PFXExportError(f"Unable to parse chain certificate {obj}: {exc}") from exc
    return pkcs12.serialize_key_and_certificates(
        name=bundle.certificate.name.encode("utf-8"), key=key, cert=cert, cas=cas or None,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
