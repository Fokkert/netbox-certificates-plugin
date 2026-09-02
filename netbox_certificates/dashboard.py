from django.template.loader import render_to_string
from extras.dashboard.utils import register_widget
from extras.dashboard.widgets import DashboardWidget
from .models import Certificate
from .services.expiry import expiry_state
from .services.status import refresh_certificate_statuses


@register_widget
class CertificateExpirationWidget(DashboardWidget):
    default_title = "Certificate Expiration"
    description = "Show certificate expiration warnings from NetBox Certificates."
    width = 5
    height = 4
    def render(self, request):
        if request.user.is_anonymous or not request.user.has_perm("netbox_certificates.view_certificate"):
            return '<div class="text-muted p-2">Permission denied.</div>'
        refresh_certificate_statuses()
        qs = Certificate.objects.all().order_by("valid_to") if request.user.is_superuser else Certificate.objects.restrict(request.user, "view").order_by("valid_to")
        states = [(cert, expiry_state(cert)) for cert in qs]
        counts = {key: sum(1 for _, state in states if state["level"] == key) for key in ("warning", "critical", "expired")}
        upcoming = [(cert, state) for cert, state in states if state["level"] in {"warning", "critical"}][:8]
        return render_to_string("netbox_certificates/dashboard_widget.html", {"counts": counts, "upcoming": upcoming})
