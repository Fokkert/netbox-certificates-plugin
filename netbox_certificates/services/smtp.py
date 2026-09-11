import ssl

from django.core.mail.backends.smtp import EmailBackend
from django.utils.functional import cached_property


class ConfigurableTLSBackend(EmailBackend):
    def __init__(self, *args, verify_tls=True, **kwargs):
        self.verify_tls = verify_tls
        super().__init__(*args, **kwargs)

    @cached_property
    def ssl_context(self):
        if self.verify_tls:
            return super().ssl_context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
