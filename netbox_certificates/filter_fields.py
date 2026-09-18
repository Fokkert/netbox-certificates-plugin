"""Optional choice filters shared by the Health UI and REST filterset."""
from django import forms
import django_filters


class OptionalMultipleChoiceField(forms.MultipleChoiceField):
    def clean(self, value):
        # A cleared multi-select may submit an empty option. Unknown non-empty
        # choices must still fail validation rather than widen the queryset.
        if isinstance(value, (list, tuple)):
            value = [item for item in value if item != ""]
        return super().clean(value)


class OptionalMultipleChoiceFilter(django_filters.MultipleChoiceFilter):
    field_class = OptionalMultipleChoiceField
