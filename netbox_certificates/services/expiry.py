import calendar
from datetime import timedelta
from django.utils import timezone
from netbox_certificates.constants import EXPIRY_CRITICAL_DAYS, EXPIRY_WARNING_DAYS


def remaining_seconds(certificate, now=None):
    now = now or timezone.now()
    if certificate.valid_to is None:
        return None
    return int((certificate.valid_to - now).total_seconds())


def remaining_days(certificate, now=None):
    seconds = remaining_seconds(certificate, now=now)
    if seconds is None:
        return None
    return int(seconds // 86400)


def expiry_state(certificate, now=None):
    now = now or timezone.now()
    days = remaining_days(certificate, now=now)
    if days is None:
        return {"level": "unknown", "days": None, "label": "Unknown"}
    seconds = remaining_seconds(certificate, now=now)
    if seconds < 0:
        return {"level": "expired", "days": days, "label": "Expired"}
    if days <= EXPIRY_CRITICAL_DAYS:
        return {"level": "critical", "days": days, "label": "Critical"}
    if days <= EXPIRY_WARNING_DAYS:
        return {"level": "warning", "days": days, "label": "Warning"}
    return {"level": "healthy", "days": days, "label": "Healthy"}


def _replace_day_safely(value, *, year, month):
    day = min(value.day, calendar.monthrange(year, month)[1])
    return value.replace(year=year, month=month, day=day)


def alert_trigger_at(valid_to, unit, value):
    if valid_to is None or not unit or not value:
        return None
    value = int(value)
    if value <= 0:
        return None
    if unit == "year":
        return _replace_day_safely(valid_to, year=valid_to.year - value, month=valid_to.month)
    if unit == "month":
        total_months = valid_to.year * 12 + (valid_to.month - 1) - value
        year, month0 = divmod(total_months, 12)
        return _replace_day_safely(valid_to, year=year, month=month0 + 1)
    delta = {
        "week": timedelta(weeks=value),
        "day": timedelta(days=value),
        "hour": timedelta(hours=value),
        "minute": timedelta(minutes=value),
        "second": timedelta(seconds=value),
    }.get(unit)
    return valid_to - delta if delta else None
