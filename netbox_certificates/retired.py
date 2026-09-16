from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.views import View


class RetiredPolicyView(LoginRequiredMixin, View):
    """Keep old bookmarks useful without exposing retired policy operations."""
    def get(self, request, *args, **kwargs):
        return redirect("plugins:netbox_certificates:alert_settings")


class CertificateAuthoritiesRedirectView(LoginRequiredMixin, View):
    def get(self, request):
        from django.urls import reverse
        query = request.GET.copy()
        query["is_ca"] = "true"
        return redirect(reverse("plugins:netbox_certificates:certificate_list") + "?" + query.urlencode())
