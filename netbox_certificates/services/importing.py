from __future__ import annotations

from django.core.exceptions import PermissionDenied
from django.db import IntegrityError, transaction

from netbox_certificates.choices import LinkOriginChoices
from netbox_certificates.models import Certificate, CSR, PrivateKey
from .duplicates import find_duplicate
from .encryption import encrypt_private_key
from .ingest import after_artifact_save
from .linker import ensure_automatic_bundle, resolve_certificate_parent


class ArtifactImportError(ValueError):
    pass


def choose_leaf(parsed_items):
    certs = [p for p in parsed_items if p.kind == "certificate"]
    if not certs:
        return None, []
    non_ca = [p for p in certs if not p.metadata.get("is_ca")]
    if len(non_ca) == 1:
        leaf = non_ca[0]
    elif len(certs) == 1:
        leaf = certs[0]
    else:
        key_fps = {
            p.metadata.get("public_key_fingerprint")
            for p in parsed_items if p.kind in {"private_key", "csr"}
        }
        matches = [p for p in certs if p.metadata.get("public_key_fingerprint") in key_fps]
        if len(matches) != 1:
            raise ArtifactImportError("Multiple certificates are present and the leaf certificate cannot be determined unambiguously.")
        leaf = matches[0]
    return leaf, [p for p in certs if p is not leaf]


def _check_created_permission(user, obj):
    if user is None:
        return
    action = f"add_{obj._meta.model_name}"
    if not user.has_perm(f"{obj._meta.app_label}.{action}"):
        raise PermissionDenied(f"You do not have permission to create {obj._meta.verbose_name} objects.")
    if hasattr(obj.__class__.objects, "restrict") and not obj.__class__.objects.restrict(user, "add").filter(pk=obj.pk).exists():
        raise PermissionDenied(f"The new {obj._meta.verbose_name} does not satisfy your object permission constraints.")


def _create(parsed, filename, owner=None):
    metadata = parsed.metadata.copy()
    common = {
        "name": parsed.name,
        "source_filename": filename,
        "source_format": parsed.source_format,
        "owner": owner,
    }
    if parsed.kind == "certificate":
        return Certificate.objects.create(material=parsed.data.decode("ascii"), **common, **metadata)
    if parsed.kind == "csr":
        return CSR.objects.create(material=parsed.data.decode("ascii"), **common, **metadata)
    if parsed.kind == "private_key":
        metadata.pop("curve", None)
        return PrivateKey.objects.create(encrypted_material=encrypt_private_key(parsed.data), **common, **metadata)
    raise ArtifactImportError(f"Unsupported artifact kind: {parsed.kind}")


def _assign_groups(objects, groups):
    groups = list(groups or [])
    if not groups:
        return
    for obj in objects:
        if hasattr(obj, "groups"):
            obj.groups.add(*groups)


def create_or_reuse_chain(parsed_chain, *, filename, user=None, owner=None, groups=None):
    created, reused, objects = [], [], []
    for parsed in parsed_chain:
        if parsed.kind != "certificate" or not parsed.metadata.get("is_ca"):
            raise ArtifactImportError("Only CA certificates may be imported as chain members.")
        duplicate = find_duplicate("certificate", parsed.metadata)
        if duplicate is not None:
            obj = Certificate.objects.get(pk=duplicate.existing_id)
            if user is not None and not Certificate.objects.restrict(user, "view").filter(pk=obj.pk).exists():
                raise PermissionDenied("A matching CA certificate already exists but is not visible to you.")
            reused.append(obj)
        else:
            obj = _create(parsed, filename, owner=owner)
            _check_created_permission(user, obj)
            created.append(obj)
            after_artifact_save(obj)
        objects.append(obj)
    _assign_groups(objects, groups)
    return objects, created, reused


def import_parsed(parsed_items, *, filename, user=None, import_chain=False, owner=None, groups=None):
    leaf, chain_parsed = choose_leaf(parsed_items)
    selected = [p for p in parsed_items if p.kind != "certificate" or p is leaf or import_chain]
    created, reused, objects_by_parsed_id = [], [], {}
    try:
        with transaction.atomic():
            for parsed in selected:
                duplicate = find_duplicate(parsed.kind, parsed.metadata)
                is_chain_ca = parsed.kind == "certificate" and parsed is not leaf and parsed.metadata.get("is_ca")
                if duplicate is not None:
                    if not is_chain_ca:
                        raise ArtifactImportError(duplicate.message())
                    existing = Certificate.objects.get(pk=duplicate.existing_id)
                    if user is not None and not Certificate.objects.restrict(user, "view").filter(pk=existing.pk).exists():
                        raise PermissionDenied("A matching CA certificate already exists but is not visible to you.")
                    obj = existing
                    reused.append(obj)
                else:
                    obj = _create(parsed, filename, owner=owner)
                    _check_created_permission(user, obj)
                    created.append(obj)
                    origin = LinkOriginChoices.PFX if parsed.source_format == "pkcs12" else LinkOriginChoices.AUTOMATIC
                    after_artifact_save(obj, origin=origin)
                objects_by_parsed_id[id(parsed)] = obj
            leaf_obj = objects_by_parsed_id.get(id(leaf)) if leaf is not None else None
            chain_objs = [objects_by_parsed_id[id(p)] for p in chain_parsed if id(p) in objects_by_parsed_id]
            for cert in [o for o in created if isinstance(o, Certificate)]:
                resolve_certificate_parent(cert)
            bundle = None
            if leaf_obj:
                resolve_certificate_parent(leaf_obj)
                bundle = ensure_automatic_bundle(leaf_obj)
                if bundle and chain_objs:
                    bundle.chain_certificates.add(*chain_objs)
                    from .linker import sync_bundle_links
                    sync_bundle_links(bundle)
            _assign_groups(created + reused + ([bundle] if bundle else []), groups)
            return {"created": created, "reused": reused, "leaf": leaf_obj, "chain": chain_objs, "bundle": bundle}
    except IntegrityError as exc:
        raise ArtifactImportError("The import collided with an existing cryptographic object. No new objects were saved.") from exc
