import json
from datetime import timedelta

import requests
from django.conf import settings
from django.core.mail import EmailMessage, get_connection
from django.db.models import Q
from django.utils import timezone

from ..choices_v1 import (
    AlertChannelTypeChoices,
    AlertEventStatusChoices,
    FindingStatusChoices,
)
from ..models_v1 import AlertEvent, AlertRule, HealthFinding


def _matches(rule, finding):
    if rule.finding_codes and finding.code not in rule.finding_codes:
        return False
    if rule.categories and finding.category not in rule.categories:
        return False
    if rule.severities and finding.severity not in rule.severities:
        return False

    if finding.status == FindingStatusChoices.RESOLVED:
        if not rule.notify_on_recovery:
            return False
    elif rule.statuses and finding.status not in rule.statuses:
        return False

    obj = finding.affected_object
    if obj is None:
        return False

    if rule.object_types and obj._meta.label_lower not in set(rule.object_types):
        return False

    if rule.owner_ids:
        owner_id = getattr(obj, "owner_id", None)
        if owner_id not in {int(value) for value in rule.owner_ids if str(value).isdigit()}:
            return False

    if rule.tag_names:
        tags = getattr(obj, "tags", None)
        if tags is None:
            return False
        object_tag_names = set(tags.values_list("name", flat=True))
        if not object_tag_names.intersection({str(value) for value in rule.tag_names}):
            return False

    if rule.expiration_days and finding.code == "CERT_EXPIRING":
        days_remaining = finding.evidence.get("days_remaining")
        if days_remaining is None or int(days_remaining) > rule.expiration_days:
            return False

    if rule.services.exists():
        service_ids = set(rule.services.values_list("pk", flat=True))
        if obj._meta.label_lower == "netbox_certificates.service":
            if obj.pk not in service_ids:
                return False
        elif hasattr(obj, "services"):
            if not obj.services.filter(pk__in=service_ids).exists():
                return False
        else:
            # A finding whose primary object is not directly service-linked can
            # still be related to a Service.
            related = finding.related_object
            if not (
                related is not None
                and related._meta.label_lower == "netbox_certificates.service"
                and related.pk in service_ids
            ):
                return False

    if rule.groups.exists():
        group_ids = set(rule.groups.values_list("pk", flat=True))
        groups = getattr(obj, "groups", None)
        if groups is None or not groups.filter(pk__in=group_ids).exists():
            return False

    if rule.policies.exists():
        policy_ids = set(rule.policies.values_list("pk", flat=True))
        if obj._meta.label_lower == "netbox_certificates.service":
            if getattr(obj, "policy_id", None) not in policy_ids:
                return False
        elif hasattr(obj, "certificate_policies"):
            if not obj.certificate_policies.filter(pk__in=policy_ids).exists():
                related = finding.related_object
                if not (
                    related is not None
                    and related._meta.label_lower == "netbox_certificates.service"
                    and getattr(related, "policy_id", None) in policy_ids
                ):
                    return False
        else:
            return False

    return True


def _recent_event(rule, channel, finding):
    delivered = AlertEvent.objects.filter(
        rule=rule,
        channel=channel,
        finding=finding,
        status=AlertEventStatusChoices.DELIVERED,
    )

    # Recovery is a one-time state transition, not a repeating condition.
    if finding.status == FindingStatusChoices.RESOLVED:
        return delivered.filter(payload_summary__finding_status=FindingStatusChoices.RESOLVED).exists()

    last = delivered.order_by("-created").first()
    if last is None:
        return False

    interval_minutes = max(rule.cooldown_minutes or 0, rule.repeat_minutes or 0)
    if interval_minutes <= 0:
        return False
    cutoff = timezone.now() - timedelta(minutes=interval_minutes)
    return bool(last.created and last.created >= cutoff)


def _payload(rule, finding):
    obj = finding.affected_object
    return {
        "rule": rule.name,
        "finding": {
            "id": finding.pk,
            "code": finding.code,
            "category": finding.category,
            "severity": finding.severity,
            "status": finding.status,
            "summary": finding.summary,
            "details": finding.details,
            "evidence": finding.evidence,
        },
        "object": {
            "type": finding.object_type.model,
            "id": finding.object_id,
            "display": str(obj) if obj is not None else None,
        },
    }




def _email_connection(channel):
    from .secret_v1 import decrypt_text
    password = decrypt_text(channel.smtp_password_encrypted, default="")
    return get_connection(
        backend="django.core.mail.backends.smtp.EmailBackend",
        host=channel.smtp_host,
        port=channel.smtp_port,
        username=channel.smtp_username or None,
        password=password or None,
        use_tls=channel.smtp_use_tls,
        use_ssl=channel.smtp_use_ssl,
        fail_silently=False,
    )


def _send_email(channel, subject, body):
    connection = _email_connection(channel)
    message = EmailMessage(
        subject=subject,
        body=body,
        from_email=channel.from_email or getattr(settings, "DEFAULT_FROM_EMAIL", None),
        to=list(channel.recipients),
        connection=connection,
    )
    return message.send(fail_silently=False)


def send_test_channel(channel):
    """Send a neutral test message without requiring or modifying a HealthFinding."""
    payload = {
        "type": "netbox-certificates-alert-test",
        "plugin_version": "1.0.4",
        "channel": channel.name,
        "timestamp": timezone.now().isoformat(),
    }
    if channel.channel_type == AlertChannelTypeChoices.EMAIL:
        _send_email(
            channel,
            f"{channel.subject_prefix} Test notification",
            json.dumps(payload, indent=2),
        )
    elif channel.channel_type == AlertChannelTypeChoices.WEBHOOK:
        from .secret_v1 import decrypt_json, decrypt_text
        response = requests.post(
            decrypt_text(channel.webhook_url_encrypted),
            json=payload,
            headers=decrypt_json(channel.webhook_headers_encrypted),
            timeout=15,
        )
        response.raise_for_status()
    else:
        raise ValueError(f"Unsupported alert channel type: {channel.channel_type}")
    return payload


def _deliver(channel, rule, finding):
    payload = _payload(rule, finding)
    if channel.channel_type == AlertChannelTypeChoices.EMAIL:
        subject = f"{channel.subject_prefix} {finding.severity.upper()}: {finding.summary}"
        body = json.dumps(payload, indent=2, default=str)
        _send_email(channel, subject, body)
    elif channel.channel_type == AlertChannelTypeChoices.WEBHOOK:
        from .secret_v1 import decrypt_json, decrypt_text
        response = requests.post(
            decrypt_text(channel.webhook_url_encrypted),
            json=payload,
            headers=decrypt_json(channel.webhook_headers_encrypted),
            timeout=15,
        )
        response.raise_for_status()
    else:
        raise ValueError(f"Unsupported alert channel type: {channel.channel_type}")
    return payload


def dispatch_alerts(rule_ids=None, bypass_cooldown=False):
    delivered = failed = skipped = 0
    findings = HealthFinding.objects.filter(
        status__in=(
            FindingStatusChoices.ACTIVE,
            FindingStatusChoices.ACKNOWLEDGED,
            FindingStatusChoices.RESOLVED,
        )
    ).select_related("object_type", "related_type")
    rules = AlertRule.objects.filter(enabled=True)
    if rule_ids is not None:
        rules = rules.filter(pk__in=list(rule_ids))
    for rule in rules.prefetch_related("channels", "services", "policies", "groups"):
        for finding in findings:
            if not _matches(rule, finding):
                continue
            for channel in rule.channels.filter(enabled=True):
                if not bypass_cooldown and _recent_event(rule, channel, finding):
                    skipped += 1
                    continue
                event = AlertEvent(
                    rule=rule,
                    channel=channel,
                    finding=finding,
                    status=AlertEventStatusChoices.FAILED,
                )
                try:
                    payload = _deliver(channel, rule, finding)
                    event.status = AlertEventStatusChoices.DELIVERED
                    event.delivered_at = timezone.now()
                    event.payload_summary = {
                        "finding_code": finding.code,
                        "severity": finding.severity,
                        "object_type": finding.object_type.model,
                        "object_id": finding.object_id,
                    }
                    delivered += 1
                except Exception as exc:
                    event.error = str(exc)[:4000]
                    failed += 1
                event.save()
    return {"delivered": delivered, "failed": failed, "skipped": skipped}
