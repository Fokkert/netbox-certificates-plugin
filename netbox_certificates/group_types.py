"""Shared group membership rules for forms, imports, REST, and ORM writes."""
from django.core.exceptions import ValidationError
from django.db.models.signals import m2m_changed, pre_save


GROUP_TYPES = (
    ("group", "Groups"), ("certificate", "Certificates"), ("privatekey", "Private Keys"),
    ("csr", "CSRs"), ("bundle", "Bundles"), ("service", "Services"), ("mixed", "Mixed (legacy)"),
)
MEMBER_RELATIONS = {"group": "children", "certificate": "certificates", "privatekey": "private_keys",
                    "csr": "csrs", "bundle": "bundles", "service": "services"}


def compatible_groups(queryset, model):
    return queryset.filter(group_type__in=(model._meta.model_name, "mixed"))


def validate_group(group):
    from .models import ArtifactGroup
    if group.group_type not in dict(GROUP_TYPES):
        raise ValidationError({"group_type": "Select a valid group type."})
    previous = ArtifactGroup.objects.filter(pk=group.pk).values_list("group_type", flat=True).first() if group.pk else None
    if group.group_type == "mixed" and previous != "mixed":
        raise ValidationError({"group_type": "Choose a specific type for this group. Mixed is reserved for existing groups."})
    if group.parent_id and group.parent.group_type not in ("group", "mixed"):
        raise ValidationError({"parent": "Only a Groups group can contain subgroups."})
    if group.pk and group.group_type != "mixed":
        for kind, relation in MEMBER_RELATIONS.items():
            if kind != group.group_type and getattr(group, relation).exists():
                raise ValidationError({"group_type": "Remove incompatible members before changing this group's type."})


def validate_memberships(sender, instance, action, reverse, model, pk_set, **kwargs):
    if action != "pre_add" or not pk_set:
        return
    from .models import ArtifactGroup
    if isinstance(instance, ArtifactGroup):
        valid = instance.group_type in (model._meta.model_name, "mixed")
    else:
        valid = not ArtifactGroup.objects.filter(pk__in=pk_set).exclude(
            group_type__in=(instance._meta.model_name, "mixed")).exists()
    if not valid:
        raise ValidationError("The selected group's type does not accept these objects.")


def validate_group_save(sender, instance, raw=False, **kwargs):
    if not raw:
        validate_group(instance)


def register_group_validation():
    from .models import ArtifactGroup, Bundle, Certificate, CSR, PrivateKey
    from .models_v1 import Service
    for model in (Certificate, PrivateKey, CSR, Bundle, Service):
        m2m_changed.connect(validate_memberships, sender=model.groups.through,
                            dispatch_uid=f"nbcert_group_type_{model._meta.model_name}")
    pre_save.connect(validate_group_save, sender=ArtifactGroup, dispatch_uid="nbcert_group_type_save")
