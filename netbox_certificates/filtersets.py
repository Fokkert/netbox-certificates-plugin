from datetime import timedelta

import django_filters
from django.db.models import Q, TextField
from django.db.models.functions import Cast
from django.utils import timezone
from netbox.filtersets import NetBoxModelFilterSet
from users.models import Owner

from .choices import (
    AlertTriggerUnitChoices,
    BundleFormatChoices,
    BundleStatusChoices,
    CertificateStatusChoices,
    SourceFormatChoices,
)
from .models import ArtifactGroup, Bundle, Certificate, CertificateAuthority, CSR, PrivateKey


class PrimaryModelFieldFilterSet(NetBoxModelFilterSet):
    """Common filters for every PrimaryModel-backed plugin list/API endpoint."""

    id = django_filters.NumberFilter()
    owner = django_filters.ModelMultipleChoiceFilter(queryset=Owner.objects.all(), distinct=True)
    description = django_filters.CharFilter(lookup_expr="icontains")
    comments = django_filters.CharFilter(lookup_expr="icontains")
    tags = django_filters.CharFilter(method="filter_tags")
    custom_field_data = django_filters.CharFilter(method="filter_custom_field_data")
    created = django_filters.IsoDateTimeFilter(field_name="created")
    created_after = django_filters.IsoDateTimeFilter(field_name="created", lookup_expr="gte")
    created_before = django_filters.IsoDateTimeFilter(field_name="created", lookup_expr="lte")
    last_updated = django_filters.IsoDateTimeFilter(field_name="last_updated")
    last_updated_after = django_filters.IsoDateTimeFilter(field_name="last_updated", lookup_expr="gte")
    last_updated_before = django_filters.IsoDateTimeFilter(field_name="last_updated", lookup_expr="lte")

    def filter_tags(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.filter(Q(tags__name__icontains=value) | Q(tags__slug__icontains=value)).distinct()

    def filter_custom_field_data(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.annotate(_custom_field_text=Cast("custom_field_data", TextField())).filter(
            _custom_field_text__icontains=value
        )


class GroupedPrimaryModelFilterSet(PrimaryModelFieldFilterSet):
    groups = django_filters.ModelMultipleChoiceFilter(queryset=ArtifactGroup.objects.all(), distinct=True)


class CertificateFilterSet(GroupedPrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    name = django_filters.CharFilter(lookup_expr="icontains")
    status = django_filters.MultipleChoiceFilter(choices=CertificateStatusChoices)
    source_filename = django_filters.CharFilter(lookup_expr="icontains")
    source_format = django_filters.MultipleChoiceFilter(choices=SourceFormatChoices)
    material = django_filters.CharFilter(lookup_expr="icontains")
    fingerprint_sha256 = django_filters.CharFilter(lookup_expr="icontains")
    public_key_fingerprint = django_filters.CharFilter(lookup_expr="icontains")
    serial_number = django_filters.CharFilter(lookup_expr="icontains")
    subject = django_filters.CharFilter(lookup_expr="icontains")
    issuer = django_filters.CharFilter(lookup_expr="icontains")
    authority = django_filters.ModelMultipleChoiceFilter(queryset=CertificateAuthority.objects.all(), distinct=True)
    subject_alternative_names = django_filters.CharFilter(method="filter_sans")
    valid_from = django_filters.IsoDateTimeFilter(field_name="valid_from")
    valid_from_after = django_filters.IsoDateTimeFilter(field_name="valid_from", lookup_expr="gte")
    valid_from_before = django_filters.IsoDateTimeFilter(field_name="valid_from", lookup_expr="lte")
    valid_to = django_filters.IsoDateTimeFilter(field_name="valid_to")
    valid_to_after = django_filters.IsoDateTimeFilter(field_name="valid_to", lookup_expr="gte")
    valid_to_before = django_filters.IsoDateTimeFilter(field_name="valid_to", lookup_expr="lte")
    expires_in_days = django_filters.NumberFilter(method="filter_expires_in_days")
    expired = django_filters.BooleanFilter(method="filter_expired")
    signature_algorithm = django_filters.CharFilter(lookup_expr="icontains")
    key_type = django_filters.CharFilter(lookup_expr="iexact")
    key_size = django_filters.NumberFilter()
    curve = django_filters.CharFilter(lookup_expr="iexact")
    is_ca = django_filters.BooleanFilter()
    parent_certificate = django_filters.ModelMultipleChoiceFilter(queryset=Certificate.objects.all(), distinct=True)
    supersedes = django_filters.ModelMultipleChoiceFilter(queryset=Certificate.objects.all(), distinct=True)
    trigger_unit = django_filters.MultipleChoiceFilter(choices=AlertTriggerUnitChoices)
    alert_trigger = django_filters.NumberFilter()

    class Meta:
        model = Certificate
        fields = []

    def search(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(source_filename__icontains=value)
            | Q(subject__icontains=value)
            | Q(issuer__icontains=value)
            | Q(serial_number__icontains=value)
            | Q(fingerprint_sha256__icontains=value)
            | Q(public_key_fingerprint__icontains=value)
            | Q(signature_algorithm__icontains=value)
            | Q(key_type__icontains=value)
            | Q(curve__icontains=value)
        ).distinct()

    def filter_sans(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.annotate(_san_text=Cast("subject_alternative_names", TextField())).filter(
            _san_text__icontains=value
        )

    def filter_expires_in_days(self, queryset, name, value):
        if value is None:
            return queryset
        try:
            days = max(0, int(value))
        except (TypeError, ValueError):
            return queryset.none()
        now = timezone.now()
        return queryset.filter(valid_to__gte=now, valid_to__lte=now + timedelta(days=days))

    def filter_expired(self, queryset, name, value):
        if value is None:
            return queryset
        now = timezone.now()
        return queryset.filter(valid_to__lt=now) if value else queryset.filter(
            Q(valid_to__gte=now) | Q(valid_to__isnull=True)
        )


class CertificateAuthorityFilterSet(PrimaryModelFieldFilterSet):
    q = django_filters.CharFilter(method="search")
    name = django_filters.CharFilter(lookup_expr="icontains")
    issuer_dn = django_filters.CharFilter(lookup_expr="icontains")
    certificates = django_filters.ModelMultipleChoiceFilter(queryset=Certificate.objects.all(), distinct=True)

    class Meta:
        model = CertificateAuthority
        fields = []

    def search(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.filter(Q(name__icontains=value) | Q(issuer_dn__icontains=value)).distinct()


class PrivateKeyFilterSet(GroupedPrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    name = django_filters.CharFilter(lookup_expr="icontains")
    source_filename = django_filters.CharFilter(lookup_expr="icontains")
    source_format = django_filters.MultipleChoiceFilter(choices=SourceFormatChoices)
    has_encrypted_material = django_filters.BooleanFilter(method="filter_has_encrypted_material")
    material_sha256 = django_filters.CharFilter(lookup_expr="icontains")
    public_key_fingerprint = django_filters.CharFilter(lookup_expr="icontains")
    key_type = django_filters.CharFilter(lookup_expr="iexact")
    key_size = django_filters.NumberFilter()
    encrypted_on_import = django_filters.BooleanFilter()

    class Meta:
        model = PrivateKey
        fields = []

    def search(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(source_filename__icontains=value)
            | Q(material_sha256__icontains=value)
            | Q(public_key_fingerprint__icontains=value)
            | Q(key_type__icontains=value)
        ).distinct()

    def filter_has_encrypted_material(self, queryset, name, value):
        if value is None:
            return queryset
        return queryset.exclude(encrypted_material=b"") if value else queryset.filter(encrypted_material=b"")


class CSRFilterSet(GroupedPrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    name = django_filters.CharFilter(lookup_expr="icontains")
    source_filename = django_filters.CharFilter(lookup_expr="icontains")
    source_format = django_filters.MultipleChoiceFilter(choices=SourceFormatChoices)
    material = django_filters.CharFilter(lookup_expr="icontains")
    fingerprint_sha256 = django_filters.CharFilter(lookup_expr="icontains")
    public_key_fingerprint = django_filters.CharFilter(lookup_expr="icontains")
    subject = django_filters.CharFilter(lookup_expr="icontains")
    subject_alternative_names = django_filters.CharFilter(method="filter_sans")
    signature_algorithm = django_filters.CharFilter(lookup_expr="icontains")
    key_type = django_filters.CharFilter(lookup_expr="iexact")
    key_size = django_filters.NumberFilter()
    curve = django_filters.CharFilter(lookup_expr="iexact")

    class Meta:
        model = CSR
        fields = []

    def search(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(source_filename__icontains=value)
            | Q(subject__icontains=value)
            | Q(fingerprint_sha256__icontains=value)
            | Q(public_key_fingerprint__icontains=value)
            | Q(signature_algorithm__icontains=value)
            | Q(key_type__icontains=value)
            | Q(curve__icontains=value)
        ).distinct()

    def filter_sans(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.annotate(_san_text=Cast("subject_alternative_names", TextField())).filter(
            _san_text__icontains=value
        )


class BundleFilterSet(GroupedPrimaryModelFilterSet):
    q = django_filters.CharFilter(method="search")
    name = django_filters.CharFilter(lookup_expr="icontains")
    identity_fingerprint = django_filters.CharFilter(lookup_expr="icontains")
    source_filename = django_filters.CharFilter(lookup_expr="icontains")
    archive_format = django_filters.MultipleChoiceFilter(choices=BundleFormatChoices)
    status = django_filters.MultipleChoiceFilter(choices=BundleStatusChoices)
    has_encrypted_archive = django_filters.BooleanFilter(method="filter_has_encrypted_archive")
    import_report = django_filters.CharFilter(method="filter_import_report")
    certificate = django_filters.ModelMultipleChoiceFilter(queryset=Certificate.objects.all(), distinct=True)
    private_key = django_filters.ModelMultipleChoiceFilter(queryset=PrivateKey.objects.all(), distinct=True)
    csr = django_filters.ModelMultipleChoiceFilter(queryset=CSR.objects.all(), distinct=True)
    chain_certificates = django_filters.ModelMultipleChoiceFilter(queryset=Certificate.objects.all(), distinct=True)

    class Meta:
        model = Bundle
        fields = []

    def search(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(source_filename__icontains=value)
            | Q(identity_fingerprint__icontains=value)
        ).distinct()

    def filter_has_encrypted_archive(self, queryset, name, value):
        if value is None:
            return queryset
        if value:
            return queryset.filter(encrypted_archive__isnull=False).exclude(encrypted_archive=b"")
        return queryset.filter(Q(encrypted_archive__isnull=True) | Q(encrypted_archive=b""))

    def filter_import_report(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.annotate(_import_report_text=Cast("import_report", TextField())).filter(
            _import_report_text__icontains=value
        )


class ArtifactGroupFilterSet(PrimaryModelFieldFilterSet):
    q = django_filters.CharFilter(method="search")
    name = django_filters.CharFilter(lookup_expr="icontains")
    parent = django_filters.ModelMultipleChoiceFilter(queryset=ArtifactGroup.objects.all(), distinct=True)
    children = django_filters.ModelMultipleChoiceFilter(queryset=ArtifactGroup.objects.all(), distinct=True)
    certificates = django_filters.ModelMultipleChoiceFilter(queryset=Certificate.objects.all(), distinct=True)
    private_keys = django_filters.ModelMultipleChoiceFilter(queryset=PrivateKey.objects.all(), distinct=True)
    csrs = django_filters.ModelMultipleChoiceFilter(queryset=CSR.objects.all(), distinct=True)
    bundles = django_filters.ModelMultipleChoiceFilter(queryset=Bundle.objects.all(), distinct=True)

    class Meta:
        model = ArtifactGroup
        fields = []

    def search(self, queryset, name, value):
        value = (value or "").strip()
        if not value:
            return queryset
        return queryset.filter(
            Q(name__icontains=value)
            | Q(description__icontains=value)
            | Q(comments__icontains=value)
        ).distinct()
