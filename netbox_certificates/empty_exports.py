"""Consistent no-data responses for UI and API exports."""
from django.http import JsonResponse
from django.shortcuts import render


def empty_export_response(request):
    warning = "There are no objects available to export with the current filters and permissions."
    if hasattr(request, "accepted_renderer"):
        return JsonResponse({"warning": warning, "count": 0})
    return render(request, "netbox_certificates/empty_export.html", {"warning": warning})


class EmptyListExportMixin:
    def get(self, request, *args, **kwargs):
        if "export" in request.GET or "_export" in request.GET:
            queryset = self.queryset.restrict(request.user, "view")
            if self.filterset:
                filters = self.filterset(request.GET, queryset=queryset, request=request)
                if filters.is_valid():
                    queryset = filters.qs
                else:
                    return super().get(request, *args, **kwargs)
            if not queryset.exists():
                return empty_export_response(request)
        return super().get(request, *args, **kwargs)
