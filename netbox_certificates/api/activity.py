"""Read-only, permission-scoped Dashboard metrics."""
from drf_spectacular.utils import extend_schema
from drf_spectacular.types import OpenApiTypes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from ..dashboard_activity import activity_summary


class ActivityAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @extend_schema(responses=OpenApiTypes.OBJECT)
    def get(self, request):
        response = Response(activity_summary(request.user))
        response["Cache-Control"] = "private, no-store"
        return response
