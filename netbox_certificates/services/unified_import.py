"""Atomic, content-detected mixed inventory imports with bounded archive expansion."""
from dataclasses import dataclass
import zipfile
import tarfile
from pathlib import PurePosixPath

from django.core.exceptions import PermissionDenied, ValidationError
from django.db import IntegrityError, transaction

from ..constants import MAX_UPLOAD_BYTES, MAX_ARCHIVE_FILES, MAX_ARCHIVE_UNCOMPRESSED_BYTES
from ..models import Certificate, CSR, PrivateKey
from ..permissions import object_allowed
from .bundles import extract_archive, is_archive, BundleImportError
from .duplicates import artifact_identity, find_duplicate
from .encryption import PrivateKeyEncryptionError, encrypt_private_key
from .importing import ArtifactImportError, _create, _check_created_permission, _check_reused_group_permissions, _assign_groups
from .linker import find_matching_bundle, link_matching_artifacts, resolve_certificate_parent, ensure_automatic_bundle, sync_bundle_links
from .parser import ArtifactParseError, parse_blob


class UnifiedImportError(ValueError):
    pass


@dataclass
class UploadItem:
    name: str
    data: bytes


def parse_uploads(uploads, *, password=None, archive_password=None, import_chain=True):
    """Parse everything before writes; filenames never select the crypto parser."""
    if not uploads:
        raise UnifiedImportError("Select at least one file to import.")
    if sum(len(item.data) for item in uploads) > MAX_UPLOAD_BYTES:
        raise UnifiedImportError(f"Combined upload exceeds {MAX_UPLOAD_BYTES} bytes.")
    records, ignored = [], []
    expanded_bytes = 0
    member_count = 0

    def read(item, depth=0, source_archive=None):
        nonlocal expanded_bytes, member_count
        if depth > 3:
            raise UnifiedImportError("Archives may be nested at most three levels.")
        member_count += 1
        expanded_bytes += len(item.data)
        if member_count > MAX_ARCHIVE_FILES or expanded_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
            raise UnifiedImportError("Import exceeds the file-count or expanded-size limit.")
        try:
            archive_input = is_archive(item.data)
        except (OSError, ValueError, tarfile.TarError, EOFError) as exc:
            raise UnifiedImportError(f"{item.name}: invalid or unreadable archive.") from exc
        if archive_input:
            try:
                _, members = extract_archive(item.data, item.name, archive_password=archive_password)
            except (BundleImportError, OSError, ValueError, zipfile.BadZipFile, tarfile.TarError, EOFError, NotImplementedError) as exc:
                raise UnifiedImportError(f"{item.name}: invalid or unreadable archive.") from exc
            for member in members:
                path = PurePosixPath(member.name.replace("\\", "/"))
                if path.is_absolute() or ".." in path.parts:
                    raise UnifiedImportError("Archive member paths must be relative and cannot contain '..'.")
                read(UploadItem(member.name, member.data), depth + 1, source_archive or item)
            return
        base = PurePosixPath(item.name).name.lower()
        if depth and ((item.name.startswith("metadata/") and base.endswith(".json")) or base in {"manifest.json", "metadata.json", "readme", "readme.txt", "readme.md"} or base == ".ds_store" or item.name.startswith("__MACOSX/")):
            ignored.append(item.name)
            return
        try:
            parsed = parse_blob(item.data, password=password, filename=item.name)
        except (ArtifactParseError, ValueError) as exc:
            raise UnifiedImportError(f"{item.name}: {exc}") from exc
        has_leaf = any(obj.kind == "certificate" and not obj.metadata.get("is_ca") for obj in parsed)
        for obj in parsed:
            if has_leaf and obj.kind == "certificate" and obj.metadata.get("is_ca") and not import_chain:
                continue
            obj._import_archive = source_archive
            records.append((item.name, obj))
            if len(records) > MAX_ARCHIVE_FILES:
                raise UnifiedImportError("Too many cryptographic objects in this request.")

    for item in uploads:
        read(item)
    if not records:
        raise UnifiedImportError("No certificate, CSR, or private key was found. Nothing was imported.")
    return records, ignored


def validate_import_records(records, allowed_kinds, *, ca_only=False):
    for filename, parsed in records:
        if ca_only and (parsed.kind != "certificate" or not parsed.metadata.get("is_ca", False)):
            raise UnifiedImportError(f"{filename}: only CA certificates (Basic Constraints CA=true) are accepted. Nothing was imported.")
        if parsed.kind not in allowed_kinds:
            raise UnifiedImportError(f"{filename}: you do not have permission to import this artifact type.")


def import_objects(*, uploads, allowed_kinds, user=None, owner=None, groups=None, password=None,
                   archive_password=None, import_chain=False, preserve_archive=True, description="", comments="", ca_only=False):
    records, ignored = parse_uploads(uploads, password=password, archive_password=archive_password, import_chain=import_chain or ca_only)
    validate_import_records(records, allowed_kinds, ca_only=ca_only)
    models = {"certificate": Certificate, "private_key": PrivateKey, "csr": CSR}
    created, reused, bundles, seen, anchors = [], [], [], set(), {}
    sources, source_fingerprints = {}, {}
    for _, parsed in records:
        source = getattr(parsed, "_import_archive", None)
        if source and (parsed.kind != "certificate" or not parsed.metadata.get("is_ca")):
            fingerprint = parsed.metadata["public_key_fingerprint"]
            sources[fingerprint] = source
            source_fingerprints.setdefault(id(source), set()).add(fingerprint)
    try:
        with transaction.atomic():
            for filename, parsed in records:
                identity = artifact_identity(parsed.kind, parsed.metadata)
                if identity in seen:
                    continue
                seen.add(identity)
                duplicate = find_duplicate(parsed.kind, parsed.metadata)
                if duplicate:
                    obj = models[parsed.kind].objects.get(pk=duplicate.existing_id)
                    if user is not None and not object_allowed(user, obj):
                        raise PermissionDenied("Matching material exists but is not visible to your account.")
                    reused.append(obj)
                else:
                    obj = _create(parsed, PurePosixPath(filename).name[:255], owner=owner)
                    obj.description, obj.comments = description, comments
                    obj.full_clean()
                    obj.save()
                    created.append(obj)
                fingerprint = getattr(obj, "public_key_fingerprint", None)
                if fingerprint:
                    anchors[fingerprint] = obj
            _check_reused_group_permissions(reused, groups, user)
            _assign_groups(created + reused, groups)
            for obj in created:
                _check_created_permission(user, obj)
            # Reconcile after all writes so order and container boundaries do not
            # affect matching. Expensive CA reconciliation runs once per request.
            from .certificate_authorities import sync_all_certificate_authorities
            from .renewal import infer_supersedes
            from .chain import ordered_chain
            for obj in created:
                link_matching_artifacts(obj)
                if isinstance(obj, Certificate):
                    infer_supersedes(obj)
            for certificate in Certificate.objects.filter(parent_certificate__isnull=True).iterator(chunk_size=200):
                resolve_certificate_parent(certificate)
            for fingerprint, obj in (anchors.items() if not ca_only else []):
                for model in models.values():
                    if user is not None and any(not object_allowed(user, peer) for peer in model.objects.filter(public_key_fingerprint=fingerprint)):
                        raise PermissionDenied("Matching relationships include material that is not visible to your account.")
                previous = find_matching_bundle(fingerprint)
                if previous and user is not None and not object_allowed(user, previous, "change"):
                    raise PermissionDenied("Change permission is required to reconcile an existing Bundle.")
                bundle = ensure_automatic_bundle(obj)
                if bundle is None:
                    continue
                if previous is None:
                    bundle.owner, bundle.description, bundle.comments = owner, description, comments
                    source = sources.get(fingerprint)
                    if preserve_archive and source and len(source_fingerprints[id(source)]) == 1:
                        bundle.encrypted_archive = encrypt_private_key(source.data)
                        bundle.source_filename = PurePosixPath(source.name).name[:255]
                    bundle.save()
                if bundle.certificate is not None:
                    bundle.chain_certificates.add(*ordered_chain(bundle.certificate))
                _assign_groups([bundle], groups)
                if previous is None:
                    _check_created_permission(user, bundle)
                sync_bundle_links(bundle)
                bundles.append(bundle)
            sync_all_certificate_authorities()
    except (ArtifactImportError, PrivateKeyEncryptionError) as exc:
        raise UnifiedImportError(str(exc)) from exc
    except (IntegrityError, ValidationError) as exc:
        raise UnifiedImportError("Import validation failed; no changes were saved. " + "; ".join(getattr(exc, "messages", ["Conflicting or invalid material."]))) from exc
    return {"mode": "objects", "created": created, "reused": reused, "bundles": bundles, "ignored_files": ignored}
