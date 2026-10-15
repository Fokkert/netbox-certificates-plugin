"""Merge exported Groups and Services; never guess cross-database PK references."""
import io
import json
import zipfile

from django.core.exceptions import ValidationError
from django.db import DatabaseError, transaction

from ..constants import MAX_UPLOAD_BYTES, MAX_ARCHIVE_FILES, MAX_ARCHIVE_UNCOMPRESSED_BYTES
from ..models import ArtifactGroup
from ..models_v1 import Service
from .backup import BackupError, plugin_models, require_backup_user, resolve, validate_reference


def read_metadata(data):
    if len(data) > MAX_UPLOAD_BYTES:
        raise BackupError("Upload exceeds 64 MiB.")
    try:
        if zipfile.is_zipfile(io.BytesIO(data)):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                members = archive.infolist()
                if len(members) > MAX_ARCHIVE_FILES or sum(item.file_size for item in members) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                    raise BackupError("Archive exceeds the file-count or expanded-size limit.")
                documents = [json.loads(archive.read(item)) for item in members if item.filename.endswith(".json") and item.filename.rsplit("/", 1)[-1] not in {"manifest.json", "snapshot.json"}]
        else:
            documents = [json.loads(data)]
        rows = [row for document in documents for row in (document if isinstance(document, list) else [document])
                if isinstance(row, dict) and row.get("type") in {"netbox_certificates.artifactgroup", "netbox_certificates.service"}]
        if not rows:
            raise BackupError("No exported Groups or Services were found. Use Restore for full backups.")
        for row in rows:
            if not isinstance(row.get("attributes"), dict) or not isinstance(row.get("relationships", {}), dict) or type(row.get("id")) is not int:
                raise BackupError("Invalid metadata object record.")
            for refs in row.get("relationships", {}).values():
                for ref in refs if isinstance(refs, list) else [refs]:
                    validate_reference(ref)
        return rows
    except (ValueError, UnicodeError, zipfile.BadZipFile, RuntimeError, NotImplementedError, RecursionError) as exc:
        if isinstance(exc, BackupError):
            raise
        raise BackupError("Invalid metadata export.") from exc


def import_metadata(data, user):
    require_backup_user(user)
    rows = read_metadata(data)
    try:
        return _merge(rows)
    except (KeyError, TypeError, ValueError, ValidationError, DatabaseError) as exc:
        if isinstance(exc, BackupError):
            raise
        raise BackupError("Metadata validation failed. Nothing was imported.") from exc


@transaction.atomic
def _merge(rows):
    registry, mapping, entries, warnings = plugin_models(), {}, [], set()
    for row in rows:
        model = registry[row["type"]]
        attrs = row["attributes"]
        matches = list(model.objects.filter(name=attrs.get("name"))[:2])
        if len(matches) > 1:
            raise BackupError("An imported name matches multiple objects; rename them before importing.")
        obj = matches[0] if matches else model()
        for field in model._meta.concrete_fields:
            if field.name in attrs and field.editable and not field.is_relation and not field.primary_key and not field.name.startswith("_"):
                setattr(obj, field.name, field.to_python(attrs[field.name]))
        if isinstance(obj, ArtifactGroup) and not obj.pk and obj.group_type == "mixed":
            # Existing exports can legitimately contain legacy mixed groups.
            obj.save_base(raw=True, force_insert=True)
        else:
            obj.full_clean()
            obj.save()
        key = (row["type"], row["id"])
        if key in mapping:
            raise BackupError("Duplicate metadata object identifier.")
        mapping[key] = obj
        entries.append((row, obj))

    def target(ref):
        if ref is None:
            return None
        key = (ref["model"], ref.get("id"))
        if key in mapping:
            return mapping[key]
        if ref["model"] in registry:
            match = ref.get("match", {})
            allowed = {"name", "fingerprint_sha256", "public_key_fingerprint", "identity_fingerprint"}
            allowed &= {field.name for field in registry[ref["model"]]._meta.concrete_fields}
            if match and set(match) <= allowed:
                matches = list(registry[ref["model"]].objects.filter(**match)[:2])
                if len(matches) == 1:
                    return matches[0]
            warnings.add(f"Missing or ambiguous {ref['model']} reference was skipped.")
            return None
        return resolve(ref, mapping, warnings)

    for row, obj in entries:
        relationships = row.get("relationships", {})
        if not relationships:
            warnings.add("Older export has no portable relationship identities; unresolved relationships were left blank.")
        allowed = {"parent", "certificates", "private_keys", "csrs", "bundles", "services", "owner", "tags"} if isinstance(obj, ArtifactGroup) else {"groups", "certificates", "private_keys", "csrs", "bundles", "owner", "policy", "tags"}
        for name, refs in relationships.items():
            if name not in allowed:
                raise BackupError("Unsupported metadata relationship.")
            if isinstance(refs, list):
                values = [value for ref in refs if (value := target(ref)) is not None]
                getattr(obj, name).set(values)
            else:
                setattr(obj, name, target(refs))
        obj.full_clean()
        obj.save()
    return {"imported": len(entries), "warnings": sorted(warnings)}
