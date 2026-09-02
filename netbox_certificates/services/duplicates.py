from dataclasses import dataclass
from netbox_certificates.models import Certificate, CSR, PrivateKey


@dataclass(frozen=True)
class DuplicateArtifact:
    kind: str
    existing_id: int
    existing_name: str
    identifier: str

    def message(self):
        labels = {"certificate": "certificate", "csr": "CSR", "private_key": "private key"}
        return (
            f"This {labels[self.kind]} already exists in NetBox Certificates "
            f"(ID {self.existing_id}, name {self.existing_name!r})."
        )


def find_duplicate(kind, metadata, *, exclude_pk=None):
    if kind == "certificate":
        identifier = metadata.get("fingerprint_sha256")
        queryset = Certificate.objects.filter(fingerprint_sha256=identifier) if identifier else Certificate.objects.none()
    elif kind == "csr":
        identifier = metadata.get("fingerprint_sha256")
        queryset = CSR.objects.filter(fingerprint_sha256=identifier) if identifier else CSR.objects.none()
    elif kind == "private_key":
        identifier = metadata.get("public_key_fingerprint")
        queryset = PrivateKey.objects.filter(public_key_fingerprint=identifier) if identifier else PrivateKey.objects.none()
    else:
        raise ValueError(f"Unsupported artifact kind: {kind!r}")
    if not identifier:
        return None
    if exclude_pk is not None:
        queryset = queryset.exclude(pk=exclude_pk)
    existing = queryset.only("pk", "name").first()
    if existing is None:
        return None
    return DuplicateArtifact(kind, existing.pk, existing.name, identifier)


def artifact_identity(kind, metadata):
    if kind in ("certificate", "csr"):
        identifier = metadata.get("fingerprint_sha256")
    elif kind == "private_key":
        identifier = metadata.get("public_key_fingerprint")
    else:
        raise ValueError(f"Unsupported artifact kind: {kind!r}")
    if not identifier:
        raise ValueError(f"Parsed {kind!r} object is missing its duplicate identifier.")
    return kind, identifier
