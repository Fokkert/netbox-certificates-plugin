"""1.0 runtime integration signals.

The pre-1.0 ArtifactLink table remains internal because the established
cryptographic reconciliation code can still write automatic relationships to
it. These signals mirror those rows into the public 1.0 ObjectLink model so
existing automatic relationship behavior is preserved without exposing the old
model/API.
"""

from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models.signals import post_delete, post_migrate, post_save
from django.dispatch import receiver

from .models import ArtifactLink as LegacyArtifactLink
from .models_v1 import ObjectLink


LEGACY_PUBLIC_MODELS = {
    "artifactlink",
    "certificateauthority",
    "expiryalertconfiguration",
    "expiryalertevent",
}


def _field_name(model, *candidates):
    names = {field.name for field in model._meta.get_fields()}
    for candidate in candidates:
        if candidate in names:
            return candidate
    return None


def _legacy_content_type(instance, field_name):
    """Resolve a legacy ContentType/ObjectType reference to ContentType."""
    field = instance._meta.get_field(field_name)
    related_model = getattr(field.remote_field, "model", None)
    label = getattr(getattr(related_model, "_meta", None), "label_lower", "")
    related = getattr(instance, field_name, None)

    if label == "contenttypes.contenttype":
        return related

    # NetBox ObjectType exposes app_label/model. Resolve it to the Django
    # ContentType used by the 1.0 GenericForeignKey.
    app_label = getattr(related, "app_label", None)
    model_name = getattr(related, "model", None)
    if app_label and model_name:
        return ContentType.objects.filter(app_label=app_label, model=model_name).first()
    return None


def _legacy_link_values(instance):
    source_type_field = _field_name(
        LegacyArtifactLink,
        "source_content_type",
        "source_object_type",
        "source_type",
    )
    source_id_field = _field_name(LegacyArtifactLink, "source_object_id", "source_id")
    target_type_field = _field_name(
        LegacyArtifactLink,
        "target_content_type",
        "target_object_type",
        "target_type",
    )
    target_id_field = _field_name(LegacyArtifactLink, "target_object_id", "target_id")
    relationship_field = _field_name(LegacyArtifactLink, "relationship", "link_type", "kind")
    label_field = _field_name(LegacyArtifactLink, "label", "name")
    enabled_field = _field_name(LegacyArtifactLink, "enabled")
    automatic_field = _field_name(LegacyArtifactLink, "automatic", "is_automatic", "managed")

    if not all((source_type_field, source_id_field, target_type_field, target_id_field)):
        return None

    source_type = _legacy_content_type(instance, source_type_field)
    target_type = _legacy_content_type(instance, target_type_field)
    source_id = getattr(instance, source_id_field, None)
    target_id = getattr(instance, target_id_field, None)
    if not all((source_type, target_type, source_id, target_id)):
        return None

    relationship = (
        str(getattr(instance, relationship_field, "related") or "related")[:80]
        if relationship_field
        else "related"
    )
    label = str(getattr(instance, label_field, "") or "")[:160] if label_field else ""
    enabled = bool(getattr(instance, enabled_field, True)) if enabled_field else True
    automatic = bool(getattr(instance, automatic_field, False)) if automatic_field else False

    return {
        "source_type": source_type,
        "source_object_id": source_id,
        "target_type": target_type,
        "target_object_id": target_id,
        "relationship": relationship,
        "label": label,
        "enabled": enabled,
        "automatic": automatic,
    }


@receiver(post_save, sender=LegacyArtifactLink)
def mirror_legacy_artifact_link(sender, instance, **kwargs):
    values = _legacy_link_values(instance)
    if values is None:
        return

    ObjectLink.objects.update_or_create(
        source_type=values["source_type"],
        source_object_id=values["source_object_id"],
        target_type=values["target_type"],
        target_object_id=values["target_object_id"],
        relationship=values["relationship"],
        defaults={
            "label": values["label"],
            "enabled": values["enabled"],
            "automatic": values["automatic"],
            "description": (
                "Automatic cryptographic relationship mirrored from the internal reconciliation engine."
                if values["automatic"]
                else "Manual pre-1.0 artifact relationship mirrored into ObjectLink."
            ),
        },
    )


@receiver(post_delete, sender=LegacyArtifactLink)
def remove_mirrored_legacy_artifact_link(sender, instance, **kwargs):
    values = _legacy_link_values(instance)
    if values is None:
        return
    ObjectLink.objects.filter(
        source_type=values["source_type"],
        source_object_id=values["source_object_id"],
        target_type=values["target_type"],
        target_object_id=values["target_object_id"],
        relationship=values["relationship"],
    ).delete()


@receiver(post_migrate)
def remove_legacy_public_permissions(sender, **kwargs):
    """Keep retained legacy models out of NetBox's public permission UI."""
    if getattr(sender, "name", None) != "netbox_certificates":
        return
    Permission.objects.filter(
        content_type__app_label="netbox_certificates",
        content_type__model__in=LEGACY_PUBLIC_MODELS,
    ).delete()
