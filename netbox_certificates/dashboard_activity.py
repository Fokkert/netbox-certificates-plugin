"""Permission-scoped Dashboard summaries; no network calls during page loads."""
from datetime import timedelta

from django.db.models import Avg, Count
from django.db.models.functions import TruncDate
from django.utils import timezone

from .activity import PrivateKeyAccessRecord, ServiceCheckRecord
from .models import Service
from .permissions import action_queryset


def activity_summary(user):
    today = timezone.localdate()
    start = today - timedelta(days=13)
    records = ServiceCheckRecord.objects.filter(created__date__gte=start)
    if not user.is_superuser:
        records = records.filter(service_id__in=action_queryset(Service, user, "view").values("pk"))
    daily = {}
    for row in records.annotate(day=TruncDate("created")).values("day", "result").annotate(total=Count("pk")).order_by():
        daily.setdefault(row["day"], {})[row["result"]] = row["total"]
    days = []
    totals = dict.fromkeys(("match", "mismatch", "failed"), 0)
    for offset in range(14):
        day = start + timedelta(days=offset)
        counts = {key: daily.get(day, {}).get(key, 0) for key in totals}
        for key, value in counts.items():
            totals[key] += value
        days.append({"date": day, **counts, "total": sum(counts.values())})
    maximum = max((day["total"] for day in days), default=0) or 1
    for day in days:
        day["segments"] = [{"result": key, "count": day[key], "height": round(day[key] * 100 / maximum, 2)} for key in totals]
    return {
        "check_days": days, "check_totals": totals, "check_total": sum(totals.values()),
        "check_average_ms": round(records.aggregate(value=Avg("duration_ms"))["value"] or 0),
        "recent_checks": list(records.values("created", "service_name", "result", "duration_ms")[:8]),
        "key_access": list(PrivateKeyAccessRecord.objects.values(
            "created", "key_name", "actor", "operation", "result", "response_status"
        )[:10]) if user.is_superuser else None,
    }
