"""Read-only operational history. Records never contain cryptographic material."""
from django.db import models
from django.utils import timezone


class ServiceCheckRecord(models.Model):
    _netbox_private = True
    created = models.DateTimeField(default=timezone.now, db_index=True)
    service_id = models.PositiveBigIntegerField(db_index=True)
    service_name = models.CharField(max_length=160)
    result = models.CharField(max_length=16, choices=[("match", "Match"), ("mismatch", "Mismatch"), ("failed", "Connection failed")])
    duration_ms = models.PositiveIntegerField(default=0)
    fingerprint = models.CharField(max_length=64, blank=True)

    class Meta:
        app_label = "netbox_certificates"
        ordering = ("-created", "-pk")
        default_permissions = ()


class PrivateKeyAccessRecord(models.Model):
    _netbox_private = True
    created = models.DateTimeField(default=timezone.now, db_index=True)
    key_id = models.PositiveBigIntegerField()
    key_name = models.CharField(max_length=160)
    actor = models.CharField(max_length=150)
    operation = models.CharField(max_length=32)
    result = models.CharField(max_length=16, choices=[("success", "Decrypted"), ("failed", "Decryption failed")])
    response_status = models.PositiveSmallIntegerField(default=200)

    class Meta:
        app_label = "netbox_certificates"
        ordering = ("-created", "-pk")
        default_permissions = ()
