from .v1_views import (
    ArtifactGroupViewSet,
    BundleViewSet,
    CertificateViewSet,
    CSRViewSet,
    PrivateKeyViewSet,
    AlertChannelViewSet,
    AlertEventViewSet,
    AlertRuleViewSet,
    CertificateAuthorityViewSet,
    CertificatePolicyViewSet,
    HealthFindingViewSet,
    ObjectLinkViewSet,
    ServiceViewSet,
)


def register_v1_routes(router):
    # 1.0 owns the complete public model router. The updater removes the
    # pre-1.0 router registrations before this function is called.
    router.register("groups", ArtifactGroupViewSet)
    router.register("certificates", CertificateViewSet)
    router.register("private-keys", PrivateKeyViewSet)
    router.register("csrs", CSRViewSet)
    router.register("bundles", BundleViewSet)
    router.register("certificate-authorities", CertificateAuthorityViewSet, basename="certificateauthority")
    router.register("services", ServiceViewSet)
    router.register("certificate-policies", CertificatePolicyViewSet)
    router.register("health-findings", HealthFindingViewSet)
    router.register("object-links", ObjectLinkViewSet)
    router.register("alert-rules", AlertRuleViewSet)
    router.register("alert-channels", AlertChannelViewSet)
    router.register("alert-events", AlertEventViewSet)
