from __future__ import annotations

import io
import os
import zipfile
from dataclasses import dataclass
from django.db import transaction

from .bundles import (
    CRYPTO_EXTENSIONS,
    BundleImportError,
    BundleImportPermissionError,
    extract_archive,
    import_bundle,
    is_archive,
)
from .importing import ArtifactImportError, import_parsed
from .parser import ArtifactParseError, parse_blob


class UnifiedImportError(ValueError):
    pass


@dataclass
class UploadItem:
    name: str
    data: bytes


def _bundle_candidate(parsed):
    keys = [p for _, p in parsed if p.kind == "private_key"]
    csrs = [p for _, p in parsed if p.kind == "csr"]
    leaves = [p for _, p in parsed if p.kind == "certificate" and not p.metadata.get("is_ca")]
    chain = [p for _, p in parsed if p.kind == "certificate" and p.metadata.get("is_ca")]
    distinct_primary_types = sum(bool(x) for x in (leaves, keys, csrs))
    if distinct_primary_types < 2:
        return False
    if any(len(items) > 1 for items in (keys, csrs, leaves)):
        raise UnifiedImportError("The selected files contain multiple candidates for the same Bundle role.")
    if chain and not leaves:
        raise UnifiedImportError("CA chain certificates cannot form a Bundle without a leaf certificate.")
    primary = [x[0] for x in (leaves, keys, csrs) if x]
    fps = {p.metadata.get("public_key_fingerprint") for p in primary}
    fps.discard(None)
    if len(fps) != 1:
        raise UnifiedImportError("The selected certificate/private-key/CSR objects do not share the same public key.")
    return True


def _zip_items(items):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for item in items:
            archive.writestr(item.name, item.data)
    return output.getvalue()


def import_objects(*, uploads, allowed_kinds, user=None, owner=None, groups=None, password=None, archive_password=None, import_chain=False, preserve_archive=True, description="", comments=""):
    items = [UploadItem(upload.name, upload.data if isinstance(upload.data, bytes) else bytes(upload.data)) for upload in uploads]
    if not items:
        raise UnifiedImportError("Select at least one file to import.")

    archive_source = None
    content_items = items
    if len(items) == 1 and is_archive(items[0].data):
        archive_source = items[0]
        try:
            _, members = extract_archive(items[0].data, items[0].name, archive_password=archive_password)
        except BundleImportError as exc:
            raise UnifiedImportError(str(exc)) from exc
        content_items = [UploadItem(member.name, member.data) for member in members]

    parsed_records = []
    parse_errors = []
    for item in content_items:
        base = os.path.basename(item.name)
        if archive_source is not None and (base.startswith(".") or item.name.startswith("__MACOSX/")):
            continue
        try:
            parsed = parse_blob(item.data, password=password, filename=item.name)
        except ArtifactParseError as exc:
            # Archives commonly contain README files or unrelated metadata. Ignore
            # those, but fail loudly when a file has a cryptographic extension so
            # corrupted certificate/key material cannot be silently skipped.
            extension = os.path.splitext(base.lower())[1]
            if archive_source is None or extension in CRYPTO_EXTENSIONS:
                parse_errors.append(f"{item.name}: {exc}")
            continue
        parsed_records.extend((item.name, p) for p in parsed)
    if parse_errors:
        raise UnifiedImportError("; ".join(parse_errors))
    if not parsed_records:
        raise UnifiedImportError("No supported certificate, private key, CSR, or Bundle content was found.")

    try:
        if _bundle_candidate(parsed_records):
            if archive_source is not None:
                bundle_bytes, bundle_name = archive_source.data, archive_source.name
            else:
                bundle_bytes, bundle_name = _zip_items(items), "imported-objects.zip"
            bundle = import_bundle(
                name="",
                archive_bytes=bundle_bytes,
                source_filename=bundle_name,
                allowed_kinds=allowed_kinds,
                archive_password=archive_password if archive_source is not None else None,
                container_password=password,
                description=description,
                comments=comments,
                owner=owner,
                preserve_archive=preserve_archive,
                import_chain=import_chain,
                user=user,
                groups=groups,
            )
            return {"mode": "bundle", "bundle": bundle, "created": [], "reused": []}

        created, reused, bundles = [], [], []
        with transaction.atomic():
            # A single object/container is imported as one logical input so PKCS#7
            # and certificate-chain behavior is retained. Archives with unrelated
            # objects are imported member-by-member.
            batches = []
            if archive_source is None and len(items) == 1:
                batches = [(items[0].name, [p for _, p in parsed_records])]
            else:
                by_name = {}
                for name, parsed in parsed_records:
                    by_name.setdefault(name, []).append(parsed)
                batches = list(by_name.items())
            for filename, parsed in batches:
                result = import_parsed(
                    parsed,
                    filename=filename,
                    user=user,
                    import_chain=import_chain,
                    owner=owner,
                    groups=groups,
                )
                created.extend(result["created"])
                reused.extend(result["reused"])
                if result.get("bundle") and result["bundle"] not in bundles:
                    bundles.append(result["bundle"])
        return {"mode": "objects", "created": created, "reused": reused, "bundles": bundles}
    except (BundleImportError, BundleImportPermissionError, ArtifactImportError) as exc:
        raise UnifiedImportError(str(exc)) from exc
