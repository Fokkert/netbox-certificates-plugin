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
    # Only fixed colors enter inline styles; notification content remains escaped.
    blue = {"accent": "#1d4ed8", "tint": "#eff6ff", "border": "#bfdbfe"}
    amber = {"accent": "#92400e", "tint": "#fffbeb", "border": "#fcd34d"}
    red = {"accent": "#b42318", "tint": "#fff1f2", "border": "#fecdd3"}
    green = {"accent": "#166534", "tint": "#f0fdf4", "border": "#bbf7d0"}
    palettes = {"critical": red, "high": red, "expired": red, "warning": amber,
                "medium": amber, "expiring": amber, "resolved": green}
    entries = [dict(entry, **palettes.get(str(entry.get("badge", "")).lower().split(" ")[0], blue))
               for entry in entries]
    palette = green if finding.get("status") == "resolved" else palettes.get(finding.get("severity"), blue)
    summary = "Your SMTP configuration successfully delivered this test notification." if test else (
        "A certificate issue has been resolved." if finding.get("status") == "resolved" else
        "Review the following certificate information in NetBox.")
    context = {"title": "Email delivery test" if test else "Certificate recovery" if finding.get("status") == "resolved" else "Certificate alert",
               "summary": summary, "entries": entries, "channel": payload.get("channel", ""),
               "version": __version__, "generated_at": timezone.now(), "palette": palette}
    lines = [context["title"], summary]
    if context["channel"]:
        lines.append(f"Channel: {context['channel']}")
    for entry in entries:
        lines.extend(["", str(entry["title"]), str(entry.get("badge", ""))])
        lines.extend(f"{label}: {value}" for label, value in entry.get("rows", []))
        lines.extend(str(entry.get(field, "")) for field in ("details", "evidence"))
    lines.extend(["", f"NetBox Certificates {__version__}", str(context["generated_at"])])
    return "\n".join(lines), render_to_string("netbox_certificates/notification_email.html", context)
