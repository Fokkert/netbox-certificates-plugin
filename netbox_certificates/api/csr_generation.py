"""Typed CSR API inputs followed by the same validation as the web form."""
from django import forms
from rest_framework import serializers

from ..forms import CSRGenerateForm


class CSRGenerationSerializer(serializers.Serializer):
    def get_fields(self):
        request = self.context.get("request")
        form = CSRGenerateForm(user=request.user if request else None)
        fields = {}
        for name, field in form.fields.items():
            options = {"required": False, "help_text": field.help_text, "label": field.label}
            if name == "sans":
                output = serializers.JSONField(**options)
            elif isinstance(field, forms.ModelMultipleChoiceField):
                output = serializers.PrimaryKeyRelatedField(queryset=field.queryset, many=True, **options)
            elif isinstance(field, forms.ModelChoiceField):
                output = serializers.PrimaryKeyRelatedField(queryset=field.queryset, allow_null=True, **options)
            elif isinstance(field, forms.BooleanField):
                output = serializers.BooleanField(**options)
            elif isinstance(field, forms.ChoiceField):
                output = serializers.ChoiceField(choices=list(field.choices), **options)
            elif isinstance(field, forms.IntegerField):
                output = serializers.IntegerField(min_value=field.min_value, max_value=field.max_value, allow_null=not field.required, **options)
            else:
                output = serializers.CharField(allow_blank=not field.required, max_length=field.max_length, **options)
            fields[name] = output
        for prefix, name in (("ku_", "key_usages"), ("eku_", "extended_key_usages")):
            fields[name] = serializers.ListField(child=serializers.ChoiceField(choices=[key[len(prefix):] for key in fields if key.startswith(prefix)]), required=False)
        return fields

    def validate(self, attrs):
        data = dict(attrs)
        for name in ("owner", "existing_private_key"):
            if data.get(name) is not None:
                data[name] = data[name].pk
        if "groups" in data:
            data["groups"] = [obj.pk for obj in data["groups"]]
        sans = data.get("sans", [])
        if isinstance(sans, list):
            entries = []
            for item in sans:
                if isinstance(item, dict) and set(item) == {"type", "value"} and all(isinstance(value, str) for value in item.values()):
                    entries.append(f"{item['type']}:{item['value']}")
                elif isinstance(item, str):
                    entries.append(item)
                else:
                    raise serializers.ValidationError({"sans": "Use SAN strings or objects with type and value."})
            data["sans"] = "\n".join(entries)
        elif not isinstance(sans, str):
            raise serializers.ValidationError({"sans": "Enter SAN strings or a list."})
        for prefix, name in (("ku_", "key_usages"), ("eku_", "extended_key_usages")):
            if name in data:
                for item in data.pop(name):
                    data[prefix + item] = True
        for name, value in (("key_algorithm", "rsa"), ("rsa_bits", 3072), ("ec_curve", "secp256r1"), ("signature_hash", "sha256"), ("rsa_signature", "pkcs1v15")):
            data.setdefault(name, value)
        form = CSRGenerateForm(data, user=self.context["request"].user)
        if not form.is_valid():
            raise serializers.ValidationError(dict(form.errors))
        return form.cleaned_data
