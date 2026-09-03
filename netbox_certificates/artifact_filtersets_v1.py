import django_filters

from .filtersets import (
    ArtifactGroupFilterSet,
    BundleFilterSet,
    CertificateFilterSet,
    CSRFilterSet,
    PrivateKeyFilterSet,
)
from .models_v1 import CertificatePolicy, Service


class ArtifactGroupV1FilterSet(ArtifactGroupFilterSet):
    service_id = django_filters.ModelMultipleChoiceFilter(
        field_name="services",
        queryset=Service.objects.all(),
        label="Service",
    )


class CertificateV1FilterSet(CertificateFilterSet):
    service_id = django_filters.ModelMultipleChoiceFilter(
        field_name="services",
        queryset=Service.objects.all(),
        label="Service",
    )
    policy_id = django_filters.ModelMultipleChoiceFilter(
        field_name="certificate_policies",
        queryset=CertificatePolicy.objects.all(),
        label="Certificate policy",
    )


class PrivateKeyV1FilterSet(PrivateKeyFilterSet):
    service_id = django_filters.ModelMultipleChoiceFilter(
        field_name="services",
        queryset=Service.objects.all(),
        label="Service",
    )


class CSRV1FilterSet(CSRFilterSet):
    service_id = django_filters.ModelMultipleChoiceFilter(
        field_name="services",
        queryset=Service.objects.all(),
        label="Service",
    )
    policy_id = django_filters.ModelMultipleChoiceFilter(
        field_name="certificate_policies",
        queryset=CertificatePolicy.objects.all(),
        label="Certificate policy",
    )


class BundleV1FilterSet(BundleFilterSet):
    service_id = django_filters.ModelMultipleChoiceFilter(
        field_name="services",
        queryset=Service.objects.all(),
        label="Service",
    )
    policy_id = django_filters.ModelMultipleChoiceFilter(
        field_name="certificate_policies",
        queryset=CertificatePolicy.objects.all(),
        label="Certificate policy",
    )
