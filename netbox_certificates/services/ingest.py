from netbox_certificates.models import Certificate, CSR, PrivateKey
from .encryption import encrypt_private_key
from .linker import ensure_automatic_bundle, link_matching_artifacts, resolve_certificate_parent
from .parser import ArtifactParseError, parse_blob


def apply_certificate(instance: Certificate, data: bytes, filename="", password=None):
    parsed = parse_blob(data, password=password, filename=filename)
    certs = [p for p in parsed if p.kind == "certificate"]
    if len(certs) != 1 or len(parsed) != 1:
        raise ArtifactParseError("Expected exactly one certificate object in this input.")
    p = certs[0]
    instance.name = instance.name or p.name
    instance.source_filename = filename or instance.source_filename
    instance.source_format = p.source_format
    instance.material = p.data.decode("ascii")
    for field, value in p.metadata.items():
        setattr(instance, field, value)
    return instance


def apply_csr(instance: CSR, data: bytes, filename="", password=None):
    parsed = parse_blob(data, password=password, filename=filename)
    csrs = [p for p in parsed if p.kind == "csr"]
    if len(csrs) != 1 or len(parsed) != 1:
        raise ArtifactParseError("Expected exactly one CSR object in this input.")
    p = csrs[0]
    instance.name = instance.name or p.name
    instance.source_filename = filename or instance.source_filename
    instance.source_format = p.source_format
    instance.material = p.data.decode("ascii")
    for field, value in p.metadata.items():
        setattr(instance, field, value)
    return instance


def apply_private_key(instance: PrivateKey, data: bytes, filename="", password=None):
    parsed = parse_blob(data, password=password, filename=filename)
    keys = [p for p in parsed if p.kind == "private_key"]
    if len(keys) != 1 or len(parsed) != 1:
        raise ArtifactParseError("Expected exactly one private key object in this input.")
    p = keys[0]
    instance.name = instance.name or p.name
    instance.source_filename = filename or instance.source_filename
    instance.source_format = p.source_format
    instance.encrypted_material = encrypt_private_key(p.data)
    for field, value in p.metadata.items():
        if field != "curve":
            setattr(instance, field, value)
    return instance


def after_artifact_save(instance, origin=None):
    from netbox_certificates.choices import LinkOriginChoices
    from .renewal import infer_supersedes
    from .certificate_authorities import sync_all_certificate_authorities

    origin = origin or LinkOriginChoices.AUTOMATIC
    link_matching_artifacts(instance, origin=origin)
    if isinstance(instance, Certificate):
        infer_supersedes(instance)
        resolve_certificate_parent(instance)
        for child in Certificate.objects.exclude(pk=instance.pk).filter(parent_certificate__isnull=True):
            resolve_certificate_parent(child)
        sync_all_certificate_authorities()
    ensure_automatic_bundle(instance, origin=origin)
