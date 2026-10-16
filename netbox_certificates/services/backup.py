"""Portable references for current Groups and Services metadata exports."""
from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import FieldError, PermissionDenied


class BackupError(ValueError):
    pass


def require_backup_user(user):
    if not user.is_active or not user.is_superuser:
        raise PermissionDenied("Metadata import requires a NetBox superuser.")


def plugin_models():
    return {model._meta.label_lower: model for model in apps.get_app_config("netbox_certificates").get_models()}


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
    validate_reference(ref)
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
        except (LookupError, FieldError):
            obj = None
    if obj is None:
        warnings.add(f"Missing or ambiguous {label} reference was skipped.")
    return obj


def validate_reference(ref):
    if ref is None:
        return
    if not isinstance(ref, dict) or not isinstance(ref.get("model"), str) or ref["model"].count(".") != 1:
        raise BackupError("Invalid object reference.")
    if "id" in ref and (type(ref["id"]) is not int or ref["id"] < 1):
        raise BackupError("Invalid referenced object identifier.")
    match = ref.get("match", {})
    if not isinstance(match, dict) or any(not isinstance(key, str) or not isinstance(value, (str, int)) for key, value in match.items()):
        raise BackupError("Invalid portable object identity.")


def custom_references(obj, user=None):
    from ..permissions import object_allowed
    result = {}
    for field in getattr(obj, "custom_fields", []):
        if field.type not in ("object", "multiobject"):
            continue
        value = field.deserialize(obj.custom_field_data.get(field.name))
        if field.type == "multiobject":
            result[field.name] = [reference(item) for item in value or [] if user is None or object_allowed(user, item)]
        else:
            result[field.name] = reference(value) if value is not None and (user is None or object_allowed(user, value)) else None
    return result


def restore_custom_references(obj, refs, resolver, warnings):
    if not isinstance(refs, dict):
        raise BackupError("Invalid custom-field references.")
    fields = {field.name: field for field in getattr(obj, "custom_fields", [])}
    for name in set(getattr(obj, "custom_field_data", {})) - set(fields):
        warnings.add(f"Custom field {name} is not defined on the destination; its value was omitted.")
    for name, field in fields.items():
        if field.type not in ("object", "multiobject"):
            continue
        value = refs.get(name)
        references = value if isinstance(value, list) else [value]
        objects = []
        for ref in references:
            validate_reference(ref)
            target = resolver(ref)
            if target is not None and isinstance(target, field.related_object_type.model_class()):
                objects.append(target)
        obj.custom_field_data[name] = field.serialize(objects if field.type == "multiobject" else (objects[0] if objects else None))
