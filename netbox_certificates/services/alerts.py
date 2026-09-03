from __future__ import annotations

import json
import smtplib
import socket
import ssl
from datetime import timedelta
from urllib import error as urlerror
from urllib import request as urlrequest
from urllib.parse import urlparse

from django.contrib.auth import get_user_model
from django.core.mail import EmailMultiAlternatives
from django.core.mail.backends.smtp import EmailBackend
from django.db import transaction
from django.template.loader import render_to_string
from django.utils import timezone

from netbox_certificates.choices import AlertMethodChoices, AlertRepeatModeChoices
from netbox_certificates.models import Bundle, Certificate, ExpiryAlertConfiguration, ExpiryAlertEvent
from netbox_certificates.services.encryption import PrivateKeyEncryptionError, decrypt_secret
from netbox_certificates.services.expiry import alert_trigger_at, remaining_days, remaining_seconds
from netbox_certificates.services.status import refresh_certificate_statuses


class ExpiryAlertError(ValueError):
    pass


class _NoRedirectHandler(urlrequest.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _recipients(config):
    values = []
    raw = (config.email_recipients or "").replace(";", ",").replace("\n", ",")
    values.extend(part.strip() for part in raw.split(",") if part.strip())
    if config.include_superusers:
        User = get_user_model()
        values.extend(User.objects.filter(is_active=True, is_superuser=True).exclude(email="").values_list("email", flat=True))
    return list(dict.fromkeys(values))


def _smtp_backend(config):
    try:
        password = decrypt_secret(config.smtp_password_encrypted)
    except PrivateKeyEncryptionError as exc:
        raise ExpiryAlertError(str(exc)) from exc
    return EmailBackend(host=config.smtp_host, port=config.smtp_port, username=config.smtp_username or None, password=password or None, use_tls=config.smtp_use_tls, use_ssl=config.smtp_use_ssl, timeout=15, fail_silently=False)


def build_alert_payload(certificate, *, now=None, test=False):
    now = now or timezone.now()
    bundles = list(Bundle.objects.filter(certificate=certificate).values("id", "name", "status")) if certificate else []
    parent = certificate.parent_certificate if certificate else None
    return {
        "event": "certificate.expiry_alert.test" if test else "certificate.expiry_alert",
        "generated_at": now.isoformat(),
        "certificate": None if certificate is None else {
            "id": certificate.pk,
            "name": certificate.name,
            "status": certificate.status,
            "status_display": certificate.get_status_display(),
            "source_filename": certificate.source_filename,
            "source_format": certificate.source_format,
            "material": certificate.material,
            "subject": certificate.subject,
            "issuer": certificate.issuer,
            "subject_alternative_names": certificate.subject_alternative_names,
            "serial_number": certificate.serial_number,
            "fingerprint_sha256": certificate.fingerprint_sha256,
            "public_key_fingerprint": certificate.public_key_fingerprint,
            "valid_from": certificate.valid_from.isoformat() if certificate.valid_from else None,
            "valid_to": certificate.valid_to.isoformat() if certificate.valid_to else None,
            "remaining_days": remaining_days(certificate, now=now),
            "remaining_seconds": remaining_seconds(certificate, now=now),
            "signature_algorithm": certificate.signature_algorithm,
            "key_type": certificate.key_type,
            "key_size": certificate.key_size,
            "curve": certificate.curve,
            "is_ca": certificate.is_ca,
            "description": certificate.description,
            "comments": certificate.comments,
            "owner": None if certificate.owner is None else {"id": certificate.owner_id, "name": str(certificate.owner)},
            "tags": list(certificate.tags.names()),
            "groups": [{"id": g.pk, "name": g.name} for g in certificate.groups.all().order_by("name")],
            "custom_fields": certificate.custom_field_data,
            "alert_trigger": certificate.alert_trigger,
            "trigger_unit": certificate.trigger_unit,
            "trigger_at": alert_trigger_at(certificate.valid_to, certificate.trigger_unit, certificate.alert_trigger).isoformat() if certificate.valid_to and certificate.trigger_unit and certificate.alert_trigger else None,
            "parent_certificate": None if parent is None else {"id": parent.pk, "name": parent.name},
            "bundles": bundles,
        },
    }


def _email_report(certificate, *, now=None):
    now = now or timezone.now()
    payload = build_alert_payload(certificate, now=now)
    cert_payload = payload["certificate"]
    seconds = cert_payload["remaining_seconds"]
    days = cert_payload["remaining_days"]
    if seconds is not None and seconds < 0:
        condition = "expired"
        condition_label = "Expired"
        condition_color = "#d63939"
        condition_text = f"Expired {abs(days)} day{'s' if abs(days) != 1 else ''} ago" if days is not None else "Expired"
    elif days is not None and days <= 7:
        condition = "critical"
        condition_label = "Critical"
        condition_color = "#d63939"
        condition_text = f"Expires in {days} day{'s' if days != 1 else ''}"
    else:
        condition = "warning"
        condition_label = "Expiring"
        condition_color = "#f59f00"
        condition_text = f"Expires in {days} day{'s' if days != 1 else ''}" if days is not None else "Expiration trigger reached"
    return {
        "certificate": certificate,
        "payload": payload,
        "condition": condition,
        "condition_label": condition_label,
        "condition_color": condition_color,
        "condition_text": condition_text,
        "remaining_days": days,
    }


def _email_subject(reports):
    if len(reports) == 1:
        report = reports[0]
        certificate = report["certificate"]
        days = report["remaining_days"]
        if report["condition"] == "expired":
            elapsed = abs(days) if days is not None else 0
            return f"Certificate expired: {certificate.name} ({elapsed} day{'s' if elapsed != 1 else ''} ago)"
        return f"Certificate expiration alert: {certificate.name} ({days} day{'s' if days != 1 else ''} remaining)"

    expired = sum(1 for report in reports if report["condition"] == "expired")
    critical = sum(1 for report in reports if report["condition"] == "critical")
    expiring = len(reports) - expired
    if expired == len(reports):
        return f"{len(reports)} certificates expired - NetBox Certificates"
    if expired:
        return f"{len(reports)} certificate expiration alerts - {expired} expired, {expiring} expiring"
    if critical:
        return f"{len(reports)} certificates expiring - {critical} critical"
    return f"{len(reports)} certificates expiring - NetBox Certificates"


def _email_text(reports):
    lines = ["NetBox Certificates expiration report", ""]
    for report in reports:
        certificate = report["certificate"]
        payload = report["payload"]["certificate"]
        lines.extend([
            f"[{report['condition_label']}] {certificate.name}",
            f"Condition: {report['condition_text']}",
            f"Expires: {certificate.valid_to}",
            f"Subject: {certificate.subject}",
            f"Issuer: {certificate.issuer}",
            f"Serial: {certificate.serial_number}",
            f"Alert trigger: {certificate.alert_trigger} {certificate.get_trigger_unit_display()}(s)",
            f"Groups: {', '.join(group['name'] for group in payload.get('groups', [])) or '-'}",
            "",
        ])
    return "\n".join(lines)


def send_email(config, certificate=None, *, certificates=None, test=False):
    recipients = _recipients(config)
    if not recipients:
        raise ExpiryAlertError("No email recipients are configured and no active NetBox superuser has an email address.")
    if not config.smtp_host or not config.smtp_port or not config.email_from_address:
        raise ExpiryAlertError("SMTP host, port, and From address are required.")

    if test:
        subject = "NetBox Certificates - Expiration Alert Test"
        text = "NetBox Certificates successfully connected to this SMTP configuration and sent a test message."
        html = render_to_string(
            "netbox_certificates/expiration_alert_email.html",
            {"test": True, "generated_at": timezone.now()},
        )
        report_count = 0
    else:
        selected = list(certificates or ([] if certificate is None else [certificate]))
        if not selected:
            raise ExpiryAlertError("No certificates were supplied for the email report.")
        now = timezone.now()
        reports = [_email_report(item, now=now) for item in selected]
        subject = _email_subject(reports)
        text = _email_text(reports)
        html = render_to_string(
            "netbox_certificates/expiration_alert_email.html",
            {
                "test": False,
                "reports": reports,
                "report_count": len(reports),
                "expired_count": sum(1 for report in reports if report["condition"] == "expired"),
                "critical_count": sum(1 for report in reports if report["condition"] == "critical"),
                "generated_at": now,
            },
        )
        report_count = len(reports)

    message = EmailMultiAlternatives(
        subject=subject,
        body=text,
        from_email=config.email_from_address,
        to=recipients,
        connection=_smtp_backend(config),
    )
    message.attach_alternative(html, "text/html")
    try:
        sent = message.send()
    except (smtplib.SMTPException, TimeoutError, OSError) as exc:
        raise ExpiryAlertError(f"SMTP connection failed: {exc}") from exc
    except Exception as exc:
        raise ExpiryAlertError(f"SMTP delivery failed: {exc.__class__.__name__}: {exc}") from exc
    if sent != 1:
        raise ExpiryAlertError("SMTP connection succeeded but the message was not accepted for delivery.")
    if test:
        return f"Test message accepted for {len(recipients)} recipient(s)."
    return f"Message accepted for {len(recipients)} recipient(s), covering {report_count} certificate(s)."


def _webhook_url(config):
    try:
        url = decrypt_secret(config.webhook_url_encrypted)
    except PrivateKeyEncryptionError as exc:
        raise ExpiryAlertError(str(exc)) from exc
    if not url:
        raise ExpiryAlertError("Webhook URL is not configured.")
    parsed = urlparse(url)
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        raise ExpiryAlertError("Webhook URL must be an absolute HTTP or HTTPS URL.")
    if parsed.scheme == "http" and not config.webhook_allow_http:
        raise ExpiryAlertError("Plain HTTP webhooks are disabled. Use HTTPS or explicitly allow insecure HTTP.")
    return url


def send_webhook(config, certificate=None, *, test=False):
    url = _webhook_url(config)
    data = json.dumps(build_alert_payload(certificate, test=test), separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "netbox-certificates-plugin/1.0.2"}
    try:
        bearer = decrypt_secret(config.webhook_bearer_token_encrypted)
    except PrivateKeyEncryptionError as exc:
        raise ExpiryAlertError(str(exc)) from exc
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"
    req = urlrequest.Request(url, data=data, headers=headers, method="POST")
    handlers = [_NoRedirectHandler()]
    if urlparse(url).scheme == "https" and config.webhook_ignore_tls_verification:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        handlers.append(urlrequest.HTTPSHandler(context=context))
    opener = urlrequest.build_opener(*handlers)
    try:
        with opener.open(req, timeout=15) as response:
            status = int(response.status)
            response.read(4096)
    except urlerror.HTTPError as exc:
        body = exc.read(1024).decode("utf-8", errors="replace")
        raise ExpiryAlertError(f"Webhook returned HTTP {exc.code}: {body[:300]}") from exc
    except urlerror.URLError as exc:
        reason = getattr(exc, "reason", exc)
        if isinstance(reason, socket.gaierror):
            hostname = urlparse(url).hostname or "configured host"
            raise ExpiryAlertError(
                f"Webhook DNS lookup failed for {hostname}: {reason}. Verify the webhook URL and DNS resolution from the NetBox host."
            ) from exc
        raise ExpiryAlertError(f"Webhook connection failed: {reason}") from exc
    except (TimeoutError, OSError) as exc:
        raise ExpiryAlertError(f"Webhook connection failed: {exc}") from exc
    except Exception as exc:
        raise ExpiryAlertError(f"Webhook request failed: {exc.__class__.__name__}: {exc}") from exc
    if not 200 <= status < 300:
        raise ExpiryAlertError(f"Webhook returned HTTP {status}.")
    return status, f"Webhook accepted the payload with HTTP {status}."


def _prepare_event(config, certificate, method, trigger_at, now):
    event, _ = ExpiryAlertEvent.objects.get_or_create(
        certificate=certificate,
        method=method,
        certificate_valid_to=certificate.valid_to,
        trigger_unit=certificate.trigger_unit,
        alert_trigger=certificate.alert_trigger,
        defaults={"trigger_at": trigger_at},
    )
    repeat = config.alert_repeat_mode == AlertRepeatModeChoices.WHILE_DUE
    if event.success and not repeat:
        return event, False
    event.trigger_at = trigger_at
    event.last_attempt_at = now
    event.attempt_count += 1
    event.status_code = None
    return event, True


def _finish_event(event, *, success, message, now, status_code=None):
    event.success = success
    event.status_code = status_code
    event.message = str(message)[:500]
    if success:
        event.delivered_at = now
    event.save(
        update_fields=(
            "trigger_at", "last_attempt_at", "attempt_count", "status_code", "success",
            "delivered_at", "message", "last_updated",
        )
    )


def _attempt_webhook(config, certificate, trigger_at, now):
    event, should_attempt = _prepare_event(config, certificate, AlertMethodChoices.WEBHOOK, trigger_at, now)
    if not should_attempt:
        return False, True, "already delivered"
    try:
        status, message = send_webhook(config, certificate)
    except Exception as exc:
        _finish_event(event, success=False, message=exc, now=now)
        return True, False, str(exc)
    _finish_event(event, success=True, message=message, now=now, status_code=status)
    return True, True, message


def _attempt_email_batch(config, due, now):
    pending = []
    for certificate, trigger_at in due:
        event, should_attempt = _prepare_event(config, certificate, AlertMethodChoices.EMAIL, trigger_at, now)
        if should_attempt:
            pending.append((event, certificate))
    if not pending:
        return 0, 0, []

    try:
        message = send_email(config, certificates=[certificate for _, certificate in pending])
    except Exception as exc:
        failures = []
        for event, certificate in pending:
            _finish_event(event, success=False, message=exc, now=now)
            failures.append(f"{certificate.name}: {exc}")
        return len(pending), 0, failures

    for event, _ in pending:
        _finish_event(event, success=True, message=message, now=now)
    return len(pending), len(pending), []


def run_expiry_alert_scan(*, force=False):
    config = ExpiryAlertConfiguration.objects.first()
    if config is None:
        return {"skipped": True, "message": "Expiration alerts are not configured."}
    now = timezone.now()
    with transaction.atomic():
        config = ExpiryAlertConfiguration.objects.select_for_update().get(pk=config.pk)
        interval = max(5, int(config.check_interval_minutes or 60))
        if not force and config.last_check_at and now - config.last_check_at < timedelta(minutes=interval):
            return {"skipped": True, "message": "Configured check interval has not elapsed."}
        config.last_check_at = now
        config.save(update_fields=("last_check_at", "last_updated"))

    if not config.email_enabled and not config.webhook_enabled:
        config.last_check_success = True
        config.last_check_message = "No alert methods are enabled."
        config.save(update_fields=("last_check_success", "last_check_message", "last_updated"))
        return {"skipped": True, "message": config.last_check_message}

    refresh_certificate_statuses()
    certificates = Certificate.objects.filter(valid_to__isnull=False).exclude(trigger_unit="").exclude(alert_trigger__isnull=True)
    if not config.alert_on_expired_certificates:
        certificates = certificates.filter(valid_to__gt=now)

    due = []
    for certificate in certificates.iterator():
        trigger_at = alert_trigger_at(certificate.valid_to, certificate.trigger_unit, certificate.alert_trigger)
        if trigger_at is not None and now >= trigger_at:
            due.append((certificate, trigger_at))

    attempts = delivered = 0
    failures = []

    if config.email_enabled:
        email_attempts, email_delivered, email_failures = _attempt_email_batch(config, due, now)
        attempts += email_attempts
        delivered += email_delivered
        failures.extend(f"Email batch: {message}" for message in email_failures)

    if config.webhook_enabled:
        for certificate, trigger_at in due:
            attempted, success, message = _attempt_webhook(config, certificate, trigger_at, now)
            if attempted:
                attempts += 1
                if success:
                    delivered += 1
                else:
                    failures.append(f"{certificate.name} / webhook: {message}")

    config.last_check_success = not failures
    if failures:
        config.last_check_message = f"{delivered} delivered, {len(failures)} failed. {failures[0]}"[:500]
    else:
        repeat_text = "repeat-while-due" if config.alert_repeat_mode == AlertRepeatModeChoices.WHILE_DUE else "once-per-trigger"
        config.last_check_message = f"Scan complete ({repeat_text}): {delivered} alert event(s) delivered from {attempts} attempt(s)."
    config.save(update_fields=("last_check_success", "last_check_message", "last_updated"))
    return {
        "skipped": False,
        "attempts": attempts,
        "delivered": delivered,
        "failures": failures,
        "message": config.last_check_message,
    }
