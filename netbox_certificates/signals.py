from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Q
from django.db.models.signals import m2m_changed, post_delete
from django.dispatch import receiver
from .choices import BundleStatusChoices
from .models import ArtifactGroup, ArtifactLink, Bundle, Certificate, CSR, PrivateKey
from .models_v1 import ObjectLink, Service


@receiver(post_delete, sender=Certificate)
@receiver(post_delete, sender=PrivateKey)
@receiver(post_delete, sender=CSR)
@receiver(post_delete, sender=Bundle)
@receiver(post_delete, sender=ArtifactGroup)
@receiver(post_delete, sender=Service)
def remove_dangling_artifact_links(sender, instance, **kwargs):
    ct = ContentType.objects.get_for_model(instance, for_concrete_model=False)
    ArtifactLink.objects.filter(Q(source_type=ct, source_id=instance.pk) | Q(target_type=ct, target_id=instance.pk)).delete()
    ObjectLink.objects.filter(Q(source_type=ct, source_object_id=instance.pk) | Q(target_type=ct, target_object_id=instance.pk)).delete()


@receiver(m2m_changed, sender=Bundle.chain_certificates.through)
def resync_bundle_chain_links(sender, instance, action, **kwargs):
    if action in {"post_add", "post_remove", "post_clear"} and instance.pk:
        from .services.linker import sync_bundle_links
        sync_bundle_links(instance)


@receiver(post_delete, sender=Certificate)
def resync_root_authorities_after_certificate_delete(sender, instance, **kwargs):
    # Deleting a root/intermediate changes the reachable trust chain for other
    # certificates. Recompute root CA identities after the transaction commits.
    using = kwargs.get("using", "default")
    connection = transaction.get_connection(using)
    # A bulk deletion emits one signal per certificate. Coalesce the full
    # inventory reconciliation to one callback in the current transaction.
    if any(getattr(callback, "_certificate_reconciliation", False) for _, callback, _ in connection.run_on_commit):
        return

    def reconcile():
        from .services.certificate_authorities import sync_all_certificate_authorities
        from .services.renewal import reconcile_supersedes
        reconcile_supersedes()
        sync_all_certificate_authorities()

    reconcile._certificate_reconciliation = True
    transaction.on_commit(reconcile, using=using)


@receiver(post_delete, sender=Certificate)
@receiver(post_delete, sender=PrivateKey)
@receiver(post_delete, sender=CSR)
def normalize_partial_bundles_after_member_delete(sender, instance, **kwargs):
    # FK SET_NULL can leave a formerly Complete Bundle missing a primary member.
    # Complete means certificate + private key + CSR, with no exceptions.
    Bundle.objects.filter(
        Q(certificate__isnull=True) | Q(private_key__isnull=True) | Q(csr__isnull=True)
    ).exclude(status=BundleStatusChoices.PARTIAL).update(status=BundleStatusChoices.PARTIAL)
