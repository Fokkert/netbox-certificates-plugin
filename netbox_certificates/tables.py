import django_tables2 as tables
from django.contrib.contenttypes.models import ContentType
from django.urls import reverse
from django.utils.html import format_html, format_html_join
from netbox.tables import NetBoxTable, columns

from .models import ArtifactGroup, ArtifactLink, Bundle, Certificate, CertificateAuthority, CSR, PrivateKey


class ArtifactRelationshipTable(NetBoxTable):
    def _can_view(self, obj):
        request = getattr(self, "request", None)
        user = getattr(request, "user", None)
        if user is None:
            return True
        manager = getattr(obj.__class__, "objects", None)
        if manager is not None and hasattr(manager, "restrict"):
            return manager.restrict(user, "view").filter(pk=obj.pk).exists()
        return True

    def _related_objects(self, record, target_model):
        if not getattr(record, "pk", None):
            return []
        record_ct = ContentType.objects.get_for_model(record, for_concrete_model=False)
        objects, seen = [], set()
        for link in ArtifactLink.for_object(record).select_related("source_type", "target_type").order_by("-pk"):
            is_source = link.source_type_id == record_ct.pk and link.source_id == record.pk
            other = link.target_object if is_source else link.source_object
            if other is None or not isinstance(other, target_model) or not self._can_view(other) or other.pk in seen:
                continue
            seen.add(other.pk)
            objects.append(other)
        return objects

    def _render_objects(self, objects):
        objects = [obj for obj in objects if obj is not None and self._can_view(obj)]
        if not objects:
            return "—"
        return format_html_join(", ", '<a href="{}">{}</a>', ((obj.get_absolute_url(), str(obj)) for obj in objects))

    def _render_related(self, record, target_model):
        return self._render_objects(self._related_objects(record, target_model))

    def render_groups(self, record):
        return self._render_objects(list(record.groups.all().order_by("name")))


class CertificateTable(ArtifactRelationshipTable):
    name = tables.Column(linkify=True)
    status = columns.ChoiceFieldColumn(
        verbose_name="Status",
        color=lambda record: {
            "active": "success",
            "expired": "danger",
            "not_yet_valid": "warning",
            "invalid": "danger",
        }.get(record.status, "secondary"),
    )
    parent_certificate = tables.Column(empty_values=(), orderable=False, verbose_name="Parent Certificate")
    valid_from = columns.DateTimeColumn(verbose_name="Valid From")
    valid_to = columns.DateTimeColumn(verbose_name="Expires At")
    authority = tables.Column(linkify=True, verbose_name="Certificate Authority")
    private_key = tables.Column(empty_values=(), orderable=False, verbose_name="Private Key")
    csr = tables.Column(empty_values=(), orderable=False, verbose_name="CSR")
    bundles = tables.Column(empty_values=(), orderable=False, verbose_name="Bundles")
    groups = tables.Column(empty_values=(), orderable=False, verbose_name="Groups")

    def render_parent_certificate(self, record):
        return self._render_objects([record.parent_certificate] if record.parent_certificate else [])

    def render_private_key(self, record):
        return self._render_related(record, PrivateKey)

    def render_csr(self, record):
        return self._render_related(record, CSR)

    def render_bundles(self, record):
        return self._render_related(record, Bundle)

    def render_groups(self, record):
        return self._render_objects(list(record.groups.all().order_by("name")))

    class Meta(NetBoxTable.Meta):
        model = Certificate
        fields = (
            "pk", "name", "status", "valid_from", "valid_to", "authority", "issuer", "is_ca",
            "parent_certificate", "private_key", "csr", "bundles", "groups", "description", "actions",
        )
        default_columns = (
            "pk", "name", "status", "valid_from", "valid_to", "authority", "parent_certificate",
            "private_key", "csr", "bundles", "groups",
        )


class CertificateAuthorityTable(NetBoxTable):
    name = tables.Column(linkify=True)
    certificates = tables.Column(empty_values=(), orderable=False, verbose_name="Certificates")

    def render_certificates(self, record):
        count = record.certificates.count()
        if not count:
            return "0"
        url = reverse("plugins:netbox_certificates:certificate_list") + f"?authority={record.pk}"
        return format_html('<a href="{}">{}</a>', url, count)

    class Meta(NetBoxTable.Meta):
        model = CertificateAuthority
        fields = ("pk", "name", "certificates", "description", "actions")
        default_columns = ("pk", "name", "certificates")


class PrivateKeyTable(ArtifactRelationshipTable):
    name = tables.Column(linkify=True)
    certificate = tables.Column(empty_values=(), orderable=False, verbose_name="Certificates")
    csr = tables.Column(empty_values=(), orderable=False, verbose_name="CSRs")
    bundles = tables.Column(empty_values=(), orderable=False, verbose_name="Bundles")
    groups = tables.Column(empty_values=(), orderable=False, verbose_name="Groups")

    def render_certificate(self, record):
        return self._render_related(record, Certificate)

    def render_csr(self, record):
        return self._render_related(record, CSR)

    def render_bundles(self, record):
        return self._render_related(record, Bundle)

    def render_groups(self, record):
        return self._render_objects(list(record.groups.all().order_by("name")))

    class Meta(NetBoxTable.Meta):
        model = PrivateKey
        fields = (
            "pk", "name", "key_type", "key_size", "public_key_fingerprint", "certificate", "csr",
            "bundles", "groups", "description", "actions",
        )
        default_columns = ("pk", "name", "key_type", "key_size", "certificate", "csr", "bundles", "groups")


class CSRTable(ArtifactRelationshipTable):
    name = tables.Column(linkify=True)
    certificate = tables.Column(empty_values=(), orderable=False, verbose_name="Certificates")
    private_key = tables.Column(empty_values=(), orderable=False, verbose_name="Private Keys")
    bundles = tables.Column(empty_values=(), orderable=False, verbose_name="Bundles")
    groups = tables.Column(empty_values=(), orderable=False, verbose_name="Groups")

    def render_certificate(self, record):
        return self._render_related(record, Certificate)

    def render_private_key(self, record):
        return self._render_related(record, PrivateKey)

    def render_bundles(self, record):
        return self._render_related(record, Bundle)

    def render_groups(self, record):
        return self._render_objects(list(record.groups.all().order_by("name")))

    class Meta(NetBoxTable.Meta):
        model = CSR
        fields = (
            "pk", "name", "subject", "key_type", "key_size", "public_key_fingerprint", "certificate",
            "private_key", "bundles", "groups", "description", "actions",
        )
        default_columns = (
            "pk", "name", "subject", "key_type", "key_size", "certificate", "private_key", "bundles", "groups",
        )


class BundleTable(ArtifactRelationshipTable):
    name = tables.Column(linkify=True)
    status = columns.ChoiceFieldColumn(
        verbose_name="Status",
        color=lambda record: {"complete": "success", "partial": "warning"}.get(record.status, "secondary"),
    )
    certificate = tables.Column(empty_values=(), orderable=False)
    private_key = tables.Column(empty_values=(), orderable=False, verbose_name="Private Key")
    csr = tables.Column(empty_values=(), orderable=False, verbose_name="CSR")
    chain_certificates = tables.Column(empty_values=(), orderable=False, verbose_name="Chain Certificates")
    groups = tables.Column(empty_values=(), orderable=False, verbose_name="Groups")

    def render_certificate(self, record):
        return self._render_objects([record.certificate] if record.certificate else [])

    def render_private_key(self, record):
        return self._render_objects([record.private_key] if record.private_key else [])

    def render_csr(self, record):
        return self._render_objects([record.csr] if record.csr else [])

    def render_chain_certificates(self, record):
        return self._render_objects(list(record.chain_certificates.all()))

    def render_groups(self, record):
        return self._render_objects(list(record.groups.all().order_by("name")))

    class Meta(NetBoxTable.Meta):
        model = Bundle
        fields = (
            "pk", "name", "status", "archive_format", "certificate", "private_key", "csr",
            "chain_certificates", "groups", "description", "actions",
        )
        default_columns = (
            "pk", "name", "status", "archive_format", "certificate", "private_key", "csr",
            "chain_certificates", "groups",
        )


class ArtifactGroupTable(ArtifactRelationshipTable):
    name = tables.Column(linkify=True)
    parent = tables.Column(linkify=True, verbose_name="Parent Group")
    members = tables.Column(empty_values=(), orderable=False, verbose_name="Members")

    def render_members(self, record):
        members = []
        members.extend(("Group", obj) for obj in record.children.all().order_by("name"))
        members.extend(("Bundle", obj) for obj in record.bundles.all().order_by("name"))
        members.extend(("Certificate", obj) for obj in record.certificates.all().order_by("name"))
        members.extend(("Private Key", obj) for obj in record.private_keys.all().order_by("name"))
        members.extend(("CSR", obj) for obj in record.csrs.all().order_by("name"))
        members = [(kind, obj) for kind, obj in members if self._can_view(obj)]
        if not members:
            return "—"
        return format_html_join(
            " ",
            '<span class="badge text-bg-secondary"><span class="fw-normal">{}:</span> <a class="text-reset text-decoration-none" href="{}">{}</a></span>',
            ((kind, obj.get_absolute_url(), str(obj)) for kind, obj in members),
        )

    class Meta(NetBoxTable.Meta):
        model = ArtifactGroup
        fields = ("pk", "name", "parent", "members", "owner", "description", "actions")
        default_columns = ("pk", "name", "parent", "members")
