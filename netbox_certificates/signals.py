from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Q
from django.db.models.signals import m2m_changed, post_delete
from django.dispatch import receiver
from .choices import BundleStatusChoices
from .models import ArtifactLink, Bundle, Certificate, CSR, PrivateKey


@receiver(post_delete, sender=Certificate)
@receiver(post_delete, sender=PrivateKey)
@receiver(post_delete, sender=CSR)
@receiver(post_delete, sender=Bundle)
def remove_dangling_artifact_links(sender, instance, **kwargs):
    ct = ContentType.objects.get_for_model(instance, for_concrete_model=False)
    ArtifactLink.objects.filter(Q(source_type=ct, source_id=instance.pk) | Q(target_type=ct, target_id=instance.pk)).delete()


@receiver(m2m_changed, sender=Bundle.chain_certificates.through)
def resync_bundle_chain_links(sender, instance, action, **kwargs):
    if action in {"post_add", "post_remove", "post_clear"} and instance.pk:
        from .services.linker import sync_bundle_links
        sync_bundle_links(instance)


@receiver(post_delete, sender=Certificate)
def resync_root_authorities_after_certificate_delete(sender, instance, **kwargs):
    # Deleting a root/intermediate changes the reachable trust chain for other
    # certificates. Recompute root CA identities after the transaction commits.
    from .services.certificate_authorities import sync_all_certificate_authorities
    transaction.on_commit(sync_all_certificate_authorities)


@receiver(post_delete, sender=Certificate)
@receiver(post_delete, sender=PrivateKey)
@receiver(post_delete, sender=CSR)
def normalize_partial_bundles_after_member_delete(sender, instance, **kwargs):
    # FK SET_NULL can leave a formerly Complete Bundle missing a primary member.
    # Complete means certificate + private key + CSR, with no exceptions.
    Bundle.objects.filter(
        Q(certificate__isnull=True) | Q(private_key__isnull=True) | Q(csr__isnull=True)
    ).exclude(status=BundleStatusChoices.PARTIAL).update(status=BundleStatusChoices.PARTIAL)
