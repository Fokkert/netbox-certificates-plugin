"""Portable, bounded plugin snapshots. Restore is atomic and superuser-only.

Database encryption is deliberately not portable: secrets are decrypted for the
snapshot and encrypted with the destination key on restore. The optional archive
password protects the entire ZIP using AES-GCM and a fixed-cost scrypt KDF.
"""
import base64
import io
import json
import os
import zipfile

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from django.apps import apps
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied, ValidationError
from django.core.serializers.json import DjangoJSONEncoder
from django.db import DatabaseError, connection, models, transaction

from ..constants import MAX_UPLOAD_BYTES, MAX_ARCHIVE_UNCOMPRESSED_BYTES
from ..version import __version__
from .encryption import decrypt_private_key, encrypt_private_key

MAGIC = b"NBCERT-BACKUP-1\x00"
FORMAT = "netbox-certificates-backup"
CONFIRMATION = "REPLACE ALL PLUGIN DATA"


class BackupError(ValueError):
    pass


def require_backup_user(user):
    if not user.is_active or not user.is_superuser:
        raise PermissionDenied("Full backup and restore require a NetBox superuser.")


def plugin_models():
    return {model._meta.label_lower: model for model in apps.get_app_config("netbox_certificates").get_models()}


def _key(password, salt):
    return Scrypt(salt=salt, length=32, n=32768, r=8, p=1).derive(password.encode("utf-8"))


def pack(document, password=""):
    raw = json.dumps(document, cls=DjangoJSONEncoder, ensure_ascii=False).encode("utf-8")
    if len(raw) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
        raise BackupError("Backup exceeds the 128 MiB expanded-size limit.")
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("snapshot.json", raw)
    data = output.getvalue()
    if password:
        salt, nonce = os.urandom(16), os.urandom(12)
        data = MAGIC + salt + nonce + AESGCM(_key(password, salt)).encrypt(nonce, data, MAGIC)
    if len(data) > MAX_UPLOAD_BYTES:
        raise BackupError("Backup exceeds the 64 MiB upload limit; no incomplete backup was returned.")
    return data


def unpack(data, password=""):
    if len(data) > MAX_UPLOAD_BYTES:
        raise BackupError("Backup exceeds the 64 MiB upload limit.")
    try:
        if data.startswith(MAGIC):
            if not password:
                raise BackupError("Enter the backup password.")
            body = data[len(MAGIC):]
            salt, nonce = body[:16], body[16:28]
            data = AESGCM(_key(password, salt)).decrypt(nonce, body[28:], MAGIC)
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            if archive.namelist() != ["snapshot.json"]:
                raise BackupError("Select a full plugin backup, not a material or inventory export.")
            member = archive.getinfo("snapshot.json")
            if member.file_size > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise BackupError("Backup exceeds the expanded-size limit.")
            with archive.open(member) as stream:
                raw = stream.read(MAX_ARCHIVE_UNCOMPRESSED_BYTES + 1)
            if len(raw) > MAX_ARCHIVE_UNCOMPRESSED_BYTES:
                raise BackupError("Backup exceeds the expanded-size limit.")
            document = json.loads(raw)
        if not isinstance(document, dict) or document.get("format") != FORMAT or document.get("schema") != 1:
            raise BackupError("Unsupported backup format.")
        if document.get("models") != sorted(plugin_models()):
            raise BackupError("Backup model schema differs. Install the same plugin version on the destination first.")
        if document.get("plugin_version") != __version__:
            raise BackupError("Install the backup's plugin version before restoring, then upgrade normally.")
        return document
    except (InvalidTag, ValueError, TypeError, KeyError, UnicodeError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        if isinstance(exc, BackupError):
            raise
        raise BackupError("Invalid backup or incorrect password. Existing data was not changed.") from exc


def reference(obj):
    if obj is None:
        return None
    label = obj._meta.label_lower
    if label.startswith("netbox_certificates."):
        identity = next((name for name in ("fingerprint_sha256", "public_key_fingerprint", "identity_fingerprint", "name") if getattr(obj, name, None)), None)
        return {"model": label, "id": obj.pk, "match": {identity: getattr(obj, identity)} if identity else {}}
    if isinstance(obj, ContentType):
        return {"model": label, "match": {"app_label": obj.app_label, "model": obj.model}}
    # Never resolve foreign NetBox objects by source database PKs.
    fields = {field.name for field in obj._meta.concrete_fields}
    for name in ("slug", "username", "name"):
        if name in fields and getattr(obj, name):
            return {"model": label, "match": {name: getattr(obj, name)}}
    return {"model": label, "match": {}}


def resolve(ref, mapping, warnings):
    if not ref:
        return None
    label = ref["model"]
    if label.startswith("netbox_certificates."):
        obj = mapping.get((label, ref.get("id")))
    else:
        try:
            model = apps.get_model(label)
            match = ref.get("match", {})
            allowed = {"slug", "username", "name"} if model is not ContentType else {"app_label", "model"}
            if not match or not set(match) <= allowed:
                obj = None
            else:
                matches = list(model._default_manager.filter(**match)[:2])
                obj = matches[0] if len(matches) == 1 else None
        except LookupError:
            obj = None
    if obj is None:
        warnings.add(f"Missing or ambiguous {label} reference was skipped.")
    return obj


def _record(obj):
    generic = [field for field in obj._meta.private_fields if isinstance(field, GenericForeignKey)]
    excluded = {name for field in generic for name in (field.ct_field, field.fk_field)}
    row = {"model": obj._meta.label_lower, "id": obj.pk, "fields": {}, "relations": {}, "generic": {}, "many": {}}
    for field in obj._meta.concrete_fields:
        if field.primary_key or field.name in excluded:
            continue
        value = getattr(obj, field.name)
        if field.is_relation:
            row["relations"][field.name] = reference(value)
        elif "encrypted" in field.name and field.name != "encrypted_on_import":
            token = value.encode("ascii") if isinstance(value, str) else value
            row["fields"][field.name] = {"secret": base64.b64encode(decrypt_private_key(token)).decode("ascii")} if token else None
        elif isinstance(field, models.BinaryField):
            row["fields"][field.name] = {"binary": base64.b64encode(bytes(value)).decode("ascii")} if value else None
        else:
            row["fields"][field.name] = value
    for field in generic:
        row["generic"][field.name] = reference(getattr(obj, field.name))
    for field in obj._meta.many_to_many:
        row["many"][field.name] = [reference(value) for value in getattr(obj, field.name).all()]
    return row


@transaction.atomic
def create_backup(user, password=""):
    require_backup_user(user)
    # Hold plugin writers while collecting a consistent snapshot.
    if connection.vendor == "postgresql":
        tables = sorted({model._meta.db_table for model in apps.get_app_config("netbox_certificates").get_models(include_auto_created=True)})
        with connection.cursor() as cursor:
            cursor.execute("LOCK TABLE " + ", ".join(connection.ops.quote_name(table) for table in tables) + " IN SHARE MODE")
    registry = plugin_models()
    document = {"format": FORMAT, "schema": 1, "plugin_version": __version__, "models": sorted(registry),
                "objects": [_record(obj) for model in registry.values() for obj in model.objects.order_by("pk").iterator()]}
    return pack(document, password)


def _decode_fields(row, model):
    values = {}
    allowed = {field.name: field for field in model._meta.concrete_fields if not field.primary_key and not field.is_relation}
    for name, value in row["fields"].items():
        field = allowed[name]
        if "encrypted" in name and name != "encrypted_on_import":
            token = encrypt_private_key(base64.b64decode(value["secret"], validate=True)) if value else None
            value = token if isinstance(field, models.BinaryField) else (token.decode("ascii") if token else "")
        elif isinstance(field, models.BinaryField):
            value = base64.b64decode(value["binary"], validate=True) if value else None
        values[name] = field.to_python(value)
    return values


def _validate_crypto(obj):
    from ..models import Certificate, CSR, PrivateKey
    from .parser import parse_blob
    if isinstance(obj, (Certificate, CSR, PrivateKey)):
        data = decrypt_private_key(obj.encrypted_material) if isinstance(obj, PrivateKey) else obj.material.encode("ascii")
        parsed = parse_blob(data)
        kind = "private_key" if isinstance(obj, PrivateKey) else obj._meta.model_name
        if len(parsed) != 1 or parsed[0].kind != kind:
            raise BackupError("Invalid cryptographic material in backup.")
        # Derive cryptographic metadata from the material, never trust JSON values.
        for name, value in parsed[0].metadata.items():
            if hasattr(obj, name):
                setattr(obj, name, value)


def restore_backup(data, user, confirmation, password=""):
    require_backup_user(user)
    if confirmation != CONFIRMATION:
        raise BackupError(f"Type {CONFIRMATION} to confirm replacement of all plugin data.")
    document = unpack(data, password)
    registry, prepared, seen = plugin_models(), [], set()
    try:
        for row in document["objects"]:
            model = registry[row["model"]]
            key = (row["model"], row["id"])
            if not isinstance(row["id"], int) or row["id"] < 1 or key in seen:
                raise BackupError("Duplicate or invalid object identifier in backup.")
            seen.add(key)
            obj = model(**_decode_fields(row, model))
            _validate_crypto(obj)
            prepared.append((row, obj))
        return _replace(prepared, registry)
    except (KeyError, TypeError, ValueError, ValidationError, DatabaseError) as exc:
        if isinstance(exc, BackupError):
            raise
        raise BackupError("Backup validation failed. Existing data was not changed.") from exc


@transaction.atomic
def _replace(prepared, registry):
    from ..models import ArtifactGroup
    from ..models_v1 import AlertSettings, HealthFinding
    from .health_v1 import _stable_fingerprint
    warnings, mapping = set(), {}
    if connection.vendor == "postgresql":
        # Block plugin writers for the complete replacement transaction.
        tables = sorted({model._meta.db_table for model in apps.get_app_config("netbox_certificates").get_models(include_auto_created=True)})
        with connection.cursor() as cursor:
            cursor.execute("LOCK TABLE " + ", ".join(connection.ops.quote_name(table) for table in tables) + " IN ACCESS EXCLUSIVE MODE")
    for model in reversed(list(registry.values())):
        model.objects.all().delete()
    pending = list(prepared)
    while pending:
        progressed = False
        for row, obj in list(pending):
            required = [field for field in obj._meta.concrete_fields if field.is_relation and not field.null]
            refs = row["relations"]
            generic = {field.name: field for field in obj._meta.private_fields if isinstance(field, GenericForeignKey)}
            unresolved = False
            for name, ref in {**refs, **row["generic"]}.items():
                if ref and ref["model"] in registry and (ref["model"], ref["id"]) not in mapping:
                    field = generic.get(name) or obj._meta.get_field(name)
                    if isinstance(field, GenericForeignKey) or not field.null:
                        unresolved = True
            if unresolved:
                continue
            missing = False
            for field in required:
                if any(field.name == g.ct_field for g in generic.values()):
                    continue
                value = resolve(refs.get(field.name), mapping, warnings)
                if value is None:
                    missing = True
                setattr(obj, field.name, value)
            for name, ref in row["generic"].items():
                value = resolve(ref, mapping, warnings)
                field = generic[name]
                if value is None and not obj._meta.get_field(field.ct_field).null:
                    missing = True
                setattr(obj, name, value)
            pending.remove((row, obj))
            progressed = True
            if missing:
                warnings.add(f"Skipped {row['model']} with a missing required external reference.")
                continue
            if isinstance(obj, AlertSettings):
                obj.pk = 1
            if isinstance(obj, HealthFinding):
                obj.fingerprint = _stable_fingerprint(obj.code, obj.affected_object, obj.related_object)
            # Raw saves preserve audit dates and do not run ingest/notification signals.
            obj.save_base(raw=True, force_insert=True)
            mapping[(row["model"], row["id"])] = obj
        if not progressed:
            raise BackupError("Backup contains missing or circular required relationships. Existing data was not changed.")
    for row, original in prepared:
        obj = mapping.get((row["model"], row["id"]))
        if obj is None:
            continue
        for name, ref in row["relations"].items():
            setattr(obj, name, resolve(ref, mapping, warnings))
        obj.save_base(raw=True, force_update=True)
    for row, original in prepared:
        obj = mapping.get((row["model"], row["id"]))
        if obj is None:
            continue
        for name, refs in row["many"].items():
            field = obj._meta.get_field(name)
            if not field.many_to_many:
                raise BackupError("Invalid many-to-many field in backup.")
            values = [value for ref in refs if (value := resolve(ref, mapping, warnings)) is not None]
            getattr(obj, name).set(values)
        # Check field constraints, service ports, group types/cycles, and links.
        obj.full_clean()
    return {"restored": len(mapping), "warnings": sorted(warnings)}
