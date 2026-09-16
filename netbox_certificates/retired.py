from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.views import View


class RetiredPolicyView(LoginRequiredMixin, View):
    """Keep old bookmarks useful without exposing retired policy operations."""
    def get(self, request, *args, **kwargs):
        return redirect("plugins:netbox_certificates:alert_settings")
