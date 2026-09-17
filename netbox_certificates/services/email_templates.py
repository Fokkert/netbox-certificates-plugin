"""Shared, escaped HTML and readable text for every certificate email."""
import json

from django.template.loader import render_to_string
from django.utils import timezone

from ..version import __version__


def render_notification(subject, payload):
    test = payload.get("type") == "netbox-certificates-alert-test" or payload.get("test", False)
    finding = payload.get("finding", {})
    entries = list(payload.get("reports", []))
    if finding:
        entries.append({
            "title": finding.get("summary", subject),
            "badge": "Resolved" if finding.get("status") == "resolved" else finding.get("severity", "Notice").upper(),
            "rows": [("Object", payload.get("object", {}).get("display") or "Unavailable"),
                     ("Rule", payload.get("rule", "")), ("Status", finding.get("status", "")),
                     ("Category", finding.get("category", "")), ("Code", finding.get("code", ""))],
            "details": finding.get("details", ""),
            "evidence": json.dumps(finding.get("evidence"), indent=2, default=str) if finding.get("evidence") else "",
        })
    summary = "Your SMTP configuration successfully delivered this test notification." if test else (
        "A certificate issue has been resolved." if finding.get("status") == "resolved" else
        "Review the following certificate information in NetBox.")
    context = {"title": "Email delivery test" if test else "Certificate recovery" if finding.get("status") == "resolved" else "Certificate alert",
               "summary": summary, "entries": entries, "channel": payload.get("channel", ""),
               "version": __version__, "generated_at": timezone.now()}
    lines = [context["title"], summary]
    if context["channel"]:
        lines.append(f"Channel: {context['channel']}")
    for entry in entries:
        lines.extend(["", str(entry["title"]), str(entry.get("badge", ""))])
        lines.extend(f"{label}: {value}" for label, value in entry.get("rows", []))
        lines.extend(str(entry.get(field, "")) for field in ("details", "evidence"))
    lines.extend(["", f"NetBox Certificates {__version__}", str(context["generated_at"])])
    return "\n".join(lines), render_to_string("netbox_certificates/notification_email.html", context)
