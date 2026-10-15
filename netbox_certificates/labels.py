"""Display labels only; API identifiers and user-supplied names stay unchanged."""
import re


_ACRONYMS = re.compile(
    r"\b(csrs?|ssl|tls|urls?|uris?|cas?|smtp|starttls|sni|sans?|rsa|ecdsa|eddsa|"
    r"ec|pem|der|pfx|pkcs|json|api|http|https|dns|ip|fqdn|sha256|sha1|cn|ou|"
    r"zip|tar|rar|id|ids)\b", re.IGNORECASE,
)


def display_label(value):
    return _ACRONYMS.sub(
        lambda match: "CSRs" if match.group().lower() == "csrs" else match.group().upper(), str(value),
    )


class AcronymFormMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        model = getattr(getattr(self, "Meta", None), "model", None) or getattr(self, "model", None)
        if "groups" in self.fields and hasattr(self.fields["groups"], "queryset") and model is not None and model._meta.model_name in {"certificate", "privatekey", "csr", "bundle", "service"}:
            self.fields["groups"].queryset = self.fields["groups"].queryset.filter(group_type__in=(model._meta.model_name, "mixed"))
        for name, field in self.fields.items():
            field.label = display_label(field.label or ("Search" if name == "q" else name.replace("_", " ").capitalize()))


class AcronymTableMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for column in self.columns:
            column.column.verbose_name = display_label(column.verbose_name)
