from netbox.search import SearchIndex, register_search
from .models import ArtifactGroup, Bundle, Certificate, CertificateAuthority, CSR, PrivateKey


@register_search
class CertificateIndex(SearchIndex):
    model = Certificate
    fields = (("name", 100), ("serial_number", 200), ("subject", 300), ("issuer", 300), ("description", 500), ("comments", 5000))
    display_attrs = ("status", "valid_to", "is_ca", "description")


@register_search
class PrivateKeyIndex(SearchIndex):
    model = PrivateKey
    fields = (("name", 100), ("public_key_fingerprint", 200), ("description", 500), ("comments", 5000))
    display_attrs = ("key_type", "key_size", "description")


@register_search
class CSRIndex(SearchIndex):
    model = CSR
    fields = (("name", 100), ("subject", 300), ("public_key_fingerprint", 300), ("description", 500), ("comments", 5000))
    display_attrs = ("key_type", "description")


@register_search
class BundleIndex(SearchIndex):
    model = Bundle
    fields = (("name", 100), ("source_filename", 300), ("description", 500), ("comments", 5000))
    display_attrs = ("status", "archive_format", "description")


@register_search
class ArtifactGroupIndex(SearchIndex):
    model = ArtifactGroup
    fields = (("name", 100), ("description", 500), ("comments", 5000))
    display_attrs = ("description",)


@register_search
class CertificateAuthorityIndex(SearchIndex):
    model = CertificateAuthority
    fields = (("name", 100), ("description", 500), ("comments", 5000))
    display_attrs = ("description",)
