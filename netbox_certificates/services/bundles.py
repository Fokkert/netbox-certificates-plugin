from __future__ import annotations

import io
import os
import tarfile
import zipfile
from dataclasses import dataclass

from django.db import IntegrityError, transaction

from netbox_certificates.choices import BundleStatusChoices, LinkOriginChoices
from netbox_certificates.constants import ALLOW_RAR, MAX_ARCHIVE_FILES, MAX_ARCHIVE_UNCOMPRESSED_BYTES
from netbox_certificates.models import Bundle, Certificate, CSR, PrivateKey
from .certificate_authorities import sync_all_certificate_authorities
from .duplicates import artifact_identity, find_duplicate
from .encryption import encrypt_private_key
from .importing import _check_created_permission
from .linker import link_matching_artifacts, resolve_certificate_parent, sync_bundle_links
from .parser import ArtifactParseError, ParsedArtifact, parse_blob

CRYPTO_EXTENSIONS = {".pem", ".crt", ".cer", ".cert", ".der", ".key", ".csr", ".req", ".pfx", ".p12", ".p7b", ".p7c", ".pkcs7"}


class BundleImportError(ValueError):
    pass


class BundleImportPermissionError(PermissionError):
    pass


@dataclass
class ArchiveMember:
    name: str
    data: bytes


def extract_archive(data: bytes, filename: str, archive_password: str | None = None):
    max_files, max_bytes = MAX_ARCHIVE_FILES, MAX_ARCHIVE_UNCOMPRESSED_BYTES
    members, total = [], 0
    if zipfile.is_zipfile(io.BytesIO(data)):
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = [i for i in archive.infolist() if not i.is_dir()]
            if len(infos) > max_files:
                raise BundleImportError(f"Archive contains {len(infos)} files; limit is {max_files}.")
            pwd = archive_password.encode() if archive_password else None
            for info in infos:
                if info.file_size > max_bytes or total + info.file_size > max_bytes:
                    raise BundleImportError("Archive exceeds the configured uncompressed-size limit.")
                try:
                    payload = archive.read(info, pwd=pwd)
                except RuntimeError as exc:
                    raise BundleImportError(f"Unable to read ZIP member {info.filename}: {exc}") from exc
                total += len(payload)
                members.append(ArchiveMember(info.filename, payload))
        return "zip", members
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as archive:
            infos = [m for m in archive.getmembers() if m.isfile()]
            if len(infos) > max_files:
                raise BundleImportError(f"Archive contains {len(infos)} files; limit is {max_files}.")
            for info in infos:
                if info.size > max_bytes or total + info.size > max_bytes:
                    raise BundleImportError("Archive exceeds the configured uncompressed-size limit.")
                fh = archive.extractfile(info)
                if fh is None:
                    continue
                payload = fh.read()
                total += len(payload)
                members.append(ArchiveMember(info.name, payload))
            return "tar", members
    except tarfile.ReadError:
        pass
    if data.startswith(b"Rar!\x1a\x07"):
        if not ALLOW_RAR:
            raise BundleImportError("RAR imports are disabled.")
        try:
            import rarfile
        except ImportError as exc:
            raise BundleImportError("RAR detected; install the plugin with the [rar] extra and an unrar/unar/bsdtar backend.") from exc
        try:
            with rarfile.RarFile(io.BytesIO(data)) as archive:
                infos = [i for i in archive.infolist() if not i.isdir()]
                if len(infos) > max_files:
                    raise BundleImportError(f"Archive contains {len(infos)} files; limit is {max_files}.")
                for info in infos:
                    if info.file_size > max_bytes or total + info.file_size > max_bytes:
                        raise BundleImportError("Archive exceeds the configured uncompressed-size limit.")
                    payload = archive.read(info, pwd=archive_password)
                    total += len(payload)
                    members.append(ArchiveMember(info.filename, payload))
            return "rar", members
        except Exception as exc:
            raise BundleImportError(f"Unable to read RAR archive: {exc}") from exc
    raise BundleImportError("Unsupported archive. Use ZIP, TAR/TAR.GZ/TGZ/TBZ/TXZ, or RAR.")


def is_archive(data: bytes):
    if zipfile.is_zipfile(io.BytesIO(data)):
        return True
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*"):
            return True
    except tarfile.ReadError:
        pass
    return data.startswith(b"Rar!\x1a\x07")


def _create_artifact(parsed: ParsedArtifact, filename: str, owner=None):
    metadata = parsed.metadata.copy()
    if parsed.kind == "certificate":
        obj = Certificate.objects.create(name=parsed.name, source_filename=filename, source_format=parsed.source_format, material=parsed.data.decode("ascii"), owner=owner, **metadata)
    elif parsed.kind == "csr":
        obj = CSR.objects.create(name=parsed.name, source_filename=filename, source_format=parsed.source_format, material=parsed.data.decode("ascii"), owner=owner, **metadata)
    elif parsed.kind == "private_key":
        metadata.pop("curve", None)
        obj = PrivateKey.objects.create(name=parsed.name, source_filename=filename, source_format=parsed.source_format, encrypted_material=encrypt_private_key(parsed.data), owner=owner, **metadata)
    else:
        raise BundleImportError(f"Unsupported parsed artifact type: {parsed.kind!r}")
    link_matching_artifacts(obj, origin=LinkOriginChoices.BUNDLE)
    return obj


def import_bundle(*, name, archive_bytes, source_filename, allowed_kinds, archive_password=None, container_password=None, description="", comments="", owner=None, preserve_archive=True, import_chain=False, user=None, groups=None):
    fmt, members = extract_archive(archive_bytes, source_filename, archive_password=archive_password)
    report = {"files": [], "ignored": [], "errors": [], "reused_chain": []}
    parsed_items = []
    for member in members:
        base = os.path.basename(member.name)
        if base.startswith(".") or member.name.startswith("__MACOSX/"):
            report["ignored"].append({"file": member.name, "reason": "metadata/hidden file"})
            continue
        try:
            parsed = parse_blob(member.data, password=container_password, filename=member.name)
        except ArtifactParseError as exc:
            ext = os.path.splitext(base.lower())[1]
            entry = {"file": member.name, "reason": str(exc)}
            (report["errors"] if ext in CRYPTO_EXTENSIONS else report["ignored"]).append(entry)
            continue
        for item in parsed:
            parsed_items.append((member.name, item))
            report["files"].append({"file": member.name, "type": item.kind, "name": item.name})
    if report["errors"]:
        details = "; ".join(f"{e['file']}: {e['reason']}" for e in report["errors"])
        raise BundleImportError(f"One or more cryptographic files are invalid: {details}")
    if not parsed_items:
        raise BundleImportError("No certificate, CSR, or private key was found in the archive.")

    keys = [p for _, p in parsed_items if p.kind == "private_key"]
    csrs = [p for _, p in parsed_items if p.kind == "csr"]
    leaves = [p for _, p in parsed_items if p.kind == "certificate" and not p.metadata.get("is_ca")]
    chain = [p for _, p in parsed_items if p.kind == "certificate" and p.metadata.get("is_ca")]
    structure_help = (
        "A Bundle must contain exactly one object for at least two of: leaf certificate, private key, CSR. "
        "Primary objects must share the same public key; CA certificates require a leaf certificate."
    )
    if len(leaves) > 1 or len(keys) > 1 or len(csrs) > 1:
        raise BundleImportError(structure_help)
    leaf = leaves[0] if leaves else None
    key = keys[0] if keys else None
    csr = csrs[0] if csrs else None
    primary_items = [p for p in (leaf, key, csr) if p is not None]
    if len(primary_items) < 2:
        raise BundleImportError(structure_help)
    if chain and leaf is None:
        raise BundleImportError("CA chain certificates require a leaf certificate. " + structure_help)
    fingerprints = {p.metadata.get("public_key_fingerprint") for p in primary_items}
    fingerprints.discard(None)
    if len(fingerprints) != 1:
        raise BundleImportError("The primary objects do not share the same public key. " + structure_help)

    selected = []
    for filename, parsed in parsed_items:
        if parsed.kind == "certificate" and parsed is not leaf and not import_chain:
            report["ignored"].append({"file": filename, "reason": "CA chain import not selected"})
            continue
        selected.append((filename, parsed))
    disallowed = {p.kind for _, p in selected} - set(allowed_kinds)
    if disallowed:
        labels = ", ".join(sorted(kind.replace("_", " ") for kind in disallowed))
        raise BundleImportPermissionError(f"You do not have permission to create all object types in this Bundle ({labels}).")

    seen, reuse_ids = {}, {}
    for filename, parsed in selected:
        identity = artifact_identity(parsed.kind, parsed.metadata)
        if identity in seen:
            raise BundleImportError(f"The archive contains the same {parsed.kind.replace('_', ' ')} more than once: {seen[identity]!r} and {filename!r}.")
        seen[identity] = filename
        duplicate = find_duplicate(parsed.kind, parsed.metadata)
        reusable_chain = duplicate is not None and parsed.kind == "certificate" and parsed is not leaf and parsed.metadata.get("is_ca")
        if duplicate is not None and not reusable_chain:
            raise BundleImportError(f"{filename}: {duplicate.message()}")
        if reusable_chain:
            existing = Certificate.objects.get(pk=duplicate.existing_id)
            if user is not None and not Certificate.objects.restrict(user, "view").filter(pk=existing.pk).exists():
                raise BundleImportPermissionError("A matching CA certificate already exists but is not visible to your account.")
            reuse_ids[id(parsed)] = existing.pk
            report["reused_chain"].append({"file": filename, "certificate_id": existing.pk})

    try:
        with transaction.atomic():
            parsed_to_obj, cert_objs, key_objs, csr_objs = {}, [], [], []
            for filename, parsed in selected:
                if id(parsed) in reuse_ids:
                    obj = Certificate.objects.get(pk=reuse_ids[id(parsed)])
                else:
                    obj = _create_artifact(parsed, filename, owner=owner)
                    _check_created_permission(user, obj)
                parsed_to_obj[id(parsed)] = obj
                if isinstance(obj, Certificate): cert_objs.append(obj)
                elif isinstance(obj, PrivateKey): key_objs.append(obj)
                else: csr_objs.append(obj)
            key_obj = next((o for o in key_objs if o.public_key_fingerprint == next(iter(fingerprints))), None)
            csr_obj = next((o for o in csr_objs if o.public_key_fingerprint == next(iter(fingerprints))), None)
            leaf_obj = parsed_to_obj.get(id(leaf)) if leaf is not None else None
            chain_objs = [parsed_to_obj[id(p)] for p in chain if id(p) in parsed_to_obj]
            identity_fingerprint = next(iter(fingerprints))
            bundle_name = name.strip() if name else ""
            if not bundle_name:
                anchor = leaf_obj or csr_obj or key_obj
                bundle_name = f"{anchor.name} Bundle"
            bundle = Bundle.objects.create(
                name=bundle_name,
                identity_fingerprint=identity_fingerprint,
                source_filename=source_filename,
                archive_format=fmt,
                status=BundleStatusChoices.COMPLETE if all((leaf_obj, key_obj, csr_obj)) else BundleStatusChoices.PARTIAL,
                encrypted_archive=encrypt_private_key(archive_bytes) if preserve_archive else None,
                import_report=report,
                certificate=leaf_obj,
                private_key=key_obj,
                csr=csr_obj,
                description=description,
                comments=comments,
                owner=owner,
            )
            _check_created_permission(user, bundle)
            if chain_objs:
                bundle.chain_certificates.set(chain_objs)
            if groups:
                bundle.groups.add(*groups)
                for obj in set(cert_objs + key_objs + csr_objs):
                    obj.groups.add(*groups)
            sync_bundle_links(bundle, origin=LinkOriginChoices.BUNDLE)
            for cert in cert_objs:
                resolve_certificate_parent(cert)
            sync_all_certificate_authorities()
            for obj in (leaf_obj, key_obj, csr_obj):
                if obj is not None:
                    link_matching_artifacts(obj, origin=LinkOriginChoices.BUNDLE)
            return bundle
    except IntegrityError as exc:
        raise BundleImportError("The bundle import collided with an existing cryptographic object. No new objects were saved.") from exc
