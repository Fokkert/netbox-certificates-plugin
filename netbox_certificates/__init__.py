from netbox.plugins import PluginConfig


class NetBoxCertificatesConfig(PluginConfig):
    name = "netbox_certificates"
    verbose_name = "NetBox Certificates Plugin"
    description = "SSL certificate, private key, CSR, bundle, Groups, CA identities, and expiration management"
    version = "0.5.0"
    base_url = "ssl-certificates"
    min_version = "4.5.9"
    max_version = "4.5.10"
    required_settings = ["encryption_key"]

    def ready(self):
        super().ready()
        from . import signals  # noqa: F401
        from . import dashboard  # noqa: F401
        from . import jobs  # noqa: F401


config = NetBoxCertificatesConfig
