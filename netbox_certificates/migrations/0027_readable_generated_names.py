"""Repair recognizable generated names while preserving custom names and material."""
import ipaddress
import re
from cryptography import x509
from django.db import migrations


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



def repair_names(apps, schema_editor):
    alias = schema_editor.connection.alias
    Certificate = apps.get_model("netbox_certificates", "Certificate")
    CSR = apps.get_model("netbox_certificates", "CSR")
    Key = apps.get_model("netbox_certificates", "PrivateKey")
    for model in (Certificate, CSR):
        for obj in model.objects.using(alias).iterator(chunk_size=200):
            try:
                subject = x509.Name.from_rfc4514_string(obj.subject)
            except ValueError:
                subject = x509.Name([])
            common = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            old_names = {obj.subject, "Unnamed"}
            if common:
                old_names.add(str(common[0].value))
            if obj.name not in old_names:
                continue
            name = identity_name(subject, obj.subject_alternative_names, f"{model.__name__} {obj.fingerprint_sha256[:12]}")
            model.objects.using(alias).filter(pk=obj.pk).update(name=name)
    for key in Key.objects.using(alias).iterator(chunk_size=200):
        fp = key.public_key_fingerprint
        if key.name not in {f"Private Key {fp[:12]}", f"Unmatched private key ({fp[:12]})"}:
            continue
        peer = Certificate.objects.using(alias).filter(public_key_fingerprint=fp).order_by("is_ca", "-valid_to", "pk").first()
        if peer is None:
            peer = CSR.objects.using(alias).filter(public_key_fingerprint=fp).order_by("pk").first()
        if peer is not None:
            try:
                subject = x509.Name.from_rfc4514_string(peer.subject)
            except ValueError:
                subject = x509.Name([])
            name = identity_name(subject, peer.subject_alternative_names, peer.name)
            Key.objects.using(alias).filter(pk=key.pk).update(name=f"{name[:188]} Private key")


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0026_typed_groups")]
    operations = [migrations.RunPython(repair_names, migrations.RunPython.noop)]
