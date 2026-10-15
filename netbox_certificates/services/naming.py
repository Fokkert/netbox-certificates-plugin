"""Readable inventory names, derived without changing cryptographic data."""
import ipaddress
import re

from cryptography import x509


def endpoint_name(value):
    value = str(value or "").strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        pass
    host = value[2:] if value.startswith("*.") else value
    try:
        ascii_host = host.rstrip(".").encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if len(ascii_host) <= 253 and all(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", part)
                                     for part in ascii_host.split(".")):
        return value
    return ""


def identity_name(subject, sans, fallback):
    """Prefer a usable CN among DNS SANs; otherwise use the first DNS/IP SAN."""
    attributes = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    cn = str(attributes[0].value).strip() if attributes else ""
    endpoints = [endpoint_name(value.split(":", 1)[1]) for value in sans
                 if isinstance(value, str) and value.startswith(("DNS:", "IP:"))]
    endpoints = [value for value in endpoints if value]
    candidate = endpoint_name(cn)
    if candidate and (not endpoints or candidate.lower() in {value.lower() for value in endpoints}):
        return candidate[:200]
    if endpoints:
        return endpoints[0][:200]
    # CA and non-server certificates may have a descriptive CN instead of DNS.
    if cn and not any(char in cn for char in ("=", "\n", "\r", "\x00")):
        return cn[:200]
    for value in sans:
        if isinstance(value, str) and value.startswith(("EMAIL:", "URI:")):
            return value.split(":", 1)[1][:200]
    return fallback[:200]


def refresh_key_names(fingerprint):
    """Rename only recognizable generated key names; keep user-assigned names."""
    from ..models import Certificate, CSR, PrivateKey
    for key in PrivateKey.objects.filter(public_key_fingerprint=fingerprint):
        generated = {f"Private Key {fingerprint[:12]}", f"Unmatched private key ({fingerprint[:12]})"}
        if key.name not in generated:
            continue
        peer = Certificate.objects.filter(public_key_fingerprint=fingerprint).order_by("is_ca", "-valid_to", "pk").first()
        if peer is None:
            peer = CSR.objects.filter(public_key_fingerprint=fingerprint).order_by("pk").first()
        if peer is None:
            continue
        try:
            subject = x509.Name.from_rfc4514_string(peer.subject)
            name = identity_name(subject, peer.subject_alternative_names, peer.name)
        except ValueError:
            name = identity_name(x509.Name([]), peer.subject_alternative_names, peer.name)
        PrivateKey.objects.filter(pk=key.pk, name=key.name).update(name=f"{name[:188]} Private key")
