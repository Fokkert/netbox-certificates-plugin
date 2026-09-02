from __future__ import annotations

import io
import os
import zipfile
from collections import defaultdict
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
        used_names = set()
        for index, item in enumerate(items, start=1):
            name = os.path.basename((item.name or f"upload-{index}").replace("\\", "/")) or f"upload-{index}"
            candidate = name
            suffix = 2
            while candidate in used_names:
                root, ext = os.path.splitext(name)
                candidate = f"{root}-{suffix}{ext}"
                suffix += 1
            used_names.add(candidate)
            archive.writestr(candidate, item.data)
    return output.getvalue()


def _primary_role(parsed):
    if parsed.kind == "private_key":
        return "private_key"
    if parsed.kind == "csr":
        return "csr"
    if parsed.kind == "certificate" and not parsed.metadata.get("is_ca"):
        return "certificate"
    return None


def _chain_records_for_leaf(leaf, ca_records):
    """Return a best-effort issuer chain from loose CA certificate records."""
    by_subject = defaultdict(list)
    for record in ca_records:
        subject = record[1].metadata.get("subject")
        if subject:
            by_subject[subject].append(record)

    result = []
    seen_subjects = set()
    issuer = leaf.metadata.get("issuer")
    for _ in range(16):
        if not issuer or issuer in seen_subjects:
            break
        seen_subjects.add(issuer)
        candidates = by_subject.get(issuer, [])
        if len(candidates) != 1:
            break
        record = candidates[0]
        result.append(record)
        parsed = record[1]
        subject = parsed.metadata.get("subject")
        next_issuer = parsed.metadata.get("issuer")
        if subject and subject == next_issuer:
            break
        issuer = next_issuer
    return result


def _loose_bundle_groups(parsed_records):
    """
    Identify independent loose Bundle candidates by public-key fingerprint.

    This enables a single request containing multiple certificate/key/CSR sets to
    create multiple Bundles. Standalone objects remain outside these groups and
    are imported normally.
    """
    by_fingerprint = defaultdict(list)
    ca_records = []

    for record in parsed_records:
        _, parsed = record
        role = _primary_role(parsed)
        if role is None:
            if parsed.kind == "certificate" and parsed.metadata.get("is_ca"):
                ca_records.append(record)
            continue
        fingerprint = parsed.metadata.get("public_key_fingerprint")
        if fingerprint:
            by_fingerprint[fingerprint].append(record)

    groups = []
    for fingerprint, records in by_fingerprint.items():
        by_role = defaultdict(list)
        for record in records:
            by_role[_primary_role(record[1])].append(record)

        distinct_roles = sum(bool(by_role[role]) for role in ("certificate", "private_key", "csr"))
        if distinct_roles < 2:
            continue
        duplicated_roles = [role for role, role_records in by_role.items() if len(role_records) > 1]
        if duplicated_roles:
            roles = ", ".join(sorted(duplicated_roles))
            raise UnifiedImportError(
                f"Public-key identity {fingerprint[:12]} has multiple candidates for Bundle role(s): {roles}. "
                "Package ambiguous Bundle candidates into separate archives."
            )

        group_records = list(records)
        leaves = by_role.get("certificate", [])
        if leaves:
            group_records.extend(_chain_records_for_leaf(leaves[0][1], ca_records))
        groups.append((fingerprint, group_records))

    if len(by_fingerprint) <= 1:
        return []
    return groups


def _items_for_records(items, records):
    names = {name for name, _ in records}
    return [item for item in items if item.name in names]


def _import_bundle_from_items(
    *,
    bundle_items,
    source_filename,
    allowed_kinds,
    user,
    owner,
    groups,
    password,
    archive_password,
    import_chain,
    preserve_archive,
    description,
    comments,
):
    archive_bytes = _zip_items(bundle_items)
    return import_bundle(
        name="",
        archive_bytes=archive_bytes,
        source_filename=source_filename,
        allowed_kinds=allowed_kinds,
        archive_password=archive_password,
        container_password=password,
        description=description,
        comments=comments,
        owner=owner,
        preserve_archive=preserve_archive,
        import_chain=import_chain,
        user=user,
        groups=groups,
    )


def _merge_result(result, created, reused, bundles):
    if result.get("mode") == "bundle":
        bundle = result["bundle"]
        if bundle not in bundles:
            bundles.append(bundle)
        if bundle not in created:
            created.append(bundle)
        return

    created.extend(result.get("created", []))
    reused.extend(result.get("reused", []))
    for bundle in result.get("bundles", []):
        if bundle not in bundles:
            bundles.append(bundle)


def import_objects(
    *,
    uploads,
    allowed_kinds,
    user=None,
    owner=None,
    groups=None,
    password=None,
    archive_password=None,
    import_chain=False,
    preserve_archive=True,
    description="",
    comments="",
):
    items = [UploadItem(upload.name, upload.data if isinstance(upload.data, bytes) else bytes(upload.data)) for upload in uploads]
    if not items:
        raise UnifiedImportError("Select at least one file to import.")

    # Treat every uploaded archive as an independent logical input. This is the
    # important difference from the original importer: five Bundle archives can
    # now be submitted in one request and are imported atomically as five Bundles.
    archive_items = [item for item in items if is_archive(item.data)]
    loose_items = [item for item in items if not is_archive(item.data)]
    if len(items) > 1 and archive_items:
        created, reused, bundles = [], [], []
        try:
            with transaction.atomic():
                for item in archive_items:
                    result = import_objects(
                        uploads=[item],
                        allowed_kinds=allowed_kinds,
                        user=user,
                        owner=owner,
                        groups=groups,
                        password=password,
                        archive_password=archive_password,
                        import_chain=import_chain,
                        preserve_archive=preserve_archive,
                        description=description,
                        comments=comments,
                    )
                    _merge_result(result, created, reused, bundles)

                if loose_items:
                    result = import_objects(
                        uploads=loose_items,
                        allowed_kinds=allowed_kinds,
                        user=user,
                        owner=owner,
                        groups=groups,
                        password=password,
                        archive_password=archive_password,
                        import_chain=import_chain,
                        preserve_archive=preserve_archive,
                        description=description,
                        comments=comments,
                    )
                    _merge_result(result, created, reused, bundles)
        except (BundleImportError, BundleImportPermissionError, ArtifactImportError) as exc:
            raise UnifiedImportError(str(exc)) from exc
        return {"mode": "objects", "created": created, "reused": reused, "bundles": bundles}

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
        loose_bundle_groups = _loose_bundle_groups(parsed_records) if archive_source is None else []
        if loose_bundle_groups:
            created, reused, bundles = [], [], []
            with transaction.atomic():
                used_names = set()
                for fingerprint, records in loose_bundle_groups:
                    bundle_items = _items_for_records(items, records)
                    if not bundle_items:
                        continue
                    bundle = _import_bundle_from_items(
                        bundle_items=bundle_items,
                        source_filename=f"bulk-bundle-{fingerprint[:12]}.zip",
                        allowed_kinds=allowed_kinds,
                        user=user,
                        owner=owner,
                        groups=groups,
                        password=password,
                        archive_password=None,
                        import_chain=import_chain,
                        preserve_archive=preserve_archive,
                        description=description,
                        comments=comments,
                    )
                    bundles.append(bundle)
                    created.append(bundle)
                    used_names.update(name for name, _ in records)

                remaining_records = [(name, parsed) for name, parsed in parsed_records if name not in used_names]
                by_name = {}
                for name, parsed in remaining_records:
                    by_name.setdefault(name, []).append(parsed)
                for filename, parsed in by_name.items():
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
