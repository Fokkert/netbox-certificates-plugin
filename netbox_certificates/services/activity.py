"""Persist measured checks even when a later health-scan transaction fails."""
from contextvars import ContextVar
from datetime import timedelta
from functools import wraps

from django.utils import timezone

from ..activity import ServiceCheckRecord

_checks = ContextVar("nbcert_check_records", default=None)


def record_check(**values):
    record = ServiceCheckRecord(**values)
    pending = _checks.get()
    if pending is None:
        record.save()
    else:
        pending.append(record)


def capture_checks(function):
    @wraps(function)
    def wrapped(*args, **kwargs):
        records = []
        token = _checks.set(records)
        try:
            return function(*args, **kwargs)
        finally:
            _checks.reset(token)
            if records:
                ServiceCheckRecord.objects.bulk_create(records)
            ServiceCheckRecord.objects.filter(created__lt=timezone.now() - timedelta(days=90)).delete()
    return wrapped
