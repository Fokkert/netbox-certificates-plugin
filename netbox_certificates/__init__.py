from netbox.plugins import PluginConfig


class NetBoxCertificatesConfig(PluginConfig):
    name = "netbox_certificates"
    verbose_name = "NetBox Certificates Plugin"
    description = "Certificate inventory, services, cryptographic relationships, health, policy, alerts, and secure material management"
    version = "1.0.0"
    base_url = "ssl-certificates"
    min_version = "4.5.9"
    max_version = "4.5.10"
    required_settings = ["encryption_key"]

    def ready(self):
        super().ready()

        # NetBox 4.5 requires plugin models to be registered explicitly for the
        # native feature registry (custom fields, tags, journaling, ownership,
        # custom model actions, etc.). Internal pre-1.0 models are already marked
        # _netbox_private and have their public permissions disabled by models_v1.
        from netbox.models.features import model_is_public, register_models
        public_models = [model for model in self.get_models() if model_is_public(model)]
        register_models(*public_models)

        # 1.0 models are imported by netbox_certificates.models during Django's
        # normal model-loading phase; ready() wires runtime integrations.
        from . import signals  # noqa: F401
        from . import signals_v1  # noqa: F401
        from . import dashboard  # noqa: F401
        from . import jobs_v1  # noqa: F401


config = NetBoxCertificatesConfig
