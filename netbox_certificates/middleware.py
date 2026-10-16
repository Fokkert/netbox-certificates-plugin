"""Collect key reads inside requests and persist after view transactions finish."""
from contextvars import ContextVar

from .activity import PrivateKeyAccessRecord


_access_context = ContextVar("nbcert_key_access", default=None)


def record_key_access(key, result):
    context = _access_context.get()
    if context is None or key is None:
        return
    request, records = context
    user = getattr(request, "user", None)
    if not user or not user.is_authenticated:
        return
    operation = "csr_signing" if "generate-csr" in request.path or "generate" in request.path else "material_export"
    # One record per key/result per request, including multi-format exports.
    records[(key.pk, result)] = {
        "key_id": key.pk, "key_name": key.name[:160], "actor": user.get_username()[:150],
        "operation": operation, "result": result,
    }


class KeyAccessAuditMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        records = {}
        token = _access_context.set((request, records))
        status = 500
        try:
            response = self.get_response(request)
            status = response.status_code
            return response
        finally:
            _access_context.reset(token)
            # Fail closed if persistence fails: do not silently serve unaudited keys.
            if records:
                PrivateKeyAccessRecord.objects.bulk_create([
                    PrivateKeyAccessRecord(**values, response_status=status) for values in records.values()
                ])
