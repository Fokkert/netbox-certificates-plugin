from django.db import migrations


def _field_name(model, *candidates):
    names = {field.name for field in model._meta.get_fields()}
    for candidate in candidates:
        if candidate in names:
            return candidate
    return None


def _content_type_id(apps, legacy_model, field_name, instance):
    """
    Normalize either Django ContentType or NetBox ObjectType references to a
    Django ContentType PK for ObjectLink.
    """
    field = legacy_model._meta.get_field(field_name)
    raw_id = getattr(instance, f"{field_name}_id", None)
    if raw_id is None:
        return None

    related_model = getattr(field.remote_field, "model", None)
    label = getattr(getattr(related_model, "_meta", None), "label_lower", "")
    if label == "contenttypes.contenttype":
        return raw_id

    # NetBox 4.5 has an ObjectType abstraction. Historical link data may use it
    # depending on which pre-1.0 revision created the row.
    related = getattr(instance, field_name, None)
    app_label = getattr(related, "app_label", None)
    model_name = getattr(related, "model", None)
    if app_label and model_name:
        ContentType = apps.get_model("contenttypes", "ContentType")
        content_type = ContentType.objects.filter(
            app_label=app_label,
            model=model_name,
        ).first()
        return content_type.pk if content_type else None
    return None


def migrate_legacy_links(apps, schema_editor):
    """Best-effort preservation of pre-1.0 generic ArtifactLink relationships."""
    try:
        LegacyLink = apps.get_model("netbox_certificates", "ArtifactLink")
        ObjectLink = apps.get_model("netbox_certificates", "ObjectLink")
    except LookupError:
        return

    src_type = _field_name(
        LegacyLink,
        "source_content_type",
        "source_object_type",
        "source_type",
    )
    src_id = _field_name(
        LegacyLink,
        "source_object_id",
        "source_id",
    )
    dst_type = _field_name(
        LegacyLink,
        "target_content_type",
        "target_object_type",
        "target_type",
    )
    dst_id = _field_name(
        LegacyLink,
        "target_object_id",
        "target_id",
    )
    relationship = _field_name(LegacyLink, "relationship", "link_type", "kind")
    label = _field_name(LegacyLink, "label", "name")
    enabled = _field_name(LegacyLink, "enabled")
    automatic = _field_name(LegacyLink, "automatic", "is_automatic", "managed")

    if not all((src_type, src_id, dst_type, dst_id)):
        return

    for old in LegacyLink.objects.all().iterator():
        source_type_id = _content_type_id(apps, LegacyLink, src_type, old)
        target_type_id = _content_type_id(apps, LegacyLink, dst_type, old)
        source_object_id = getattr(old, src_id, None)
        target_object_id = getattr(old, dst_id, None)
        if not all((source_type_id, target_type_id, source_object_id, target_object_id)):
            continue

        ObjectLink.objects.get_or_create(
            source_type_id=source_type_id,
            source_object_id=source_object_id,
            target_type_id=target_type_id,
            target_object_id=target_object_id,
            relationship=(
                str(getattr(old, relationship, "related") or "related")[:80]
                if relationship
                else "related"
            ),
            defaults={
                "label": str(getattr(old, label, "") or "")[:160] if label else "",
                "enabled": bool(getattr(old, enabled, True)) if enabled else True,
                "automatic": bool(getattr(old, automatic, False)) if automatic else False,
                "description": "Migrated from a pre-1.0 artifact relationship.",
            },
        )


def reverse_noop(apps, schema_editor):
    # 1.0 intentionally generalizes links. Reconstructing the old relation type
    # from arbitrary NetBox ObjectLinks is ambiguous and is not attempted.
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("netbox_certificates", "0014_certificate_management_v1"),
    ]

    operations = [
        migrations.RunPython(migrate_legacy_links, reverse_noop),
    ]
