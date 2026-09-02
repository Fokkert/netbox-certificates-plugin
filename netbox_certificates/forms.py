from __future__ import annotations

from django import forms
from django.core.exceptions import ValidationError
from django.db import transaction
from core.models import ObjectType
from users.models import Owner
from utilities.forms.fields import DynamicModelChoiceField, DynamicModelMultipleChoiceField
from utilities.forms.rendering import FieldSet
from netbox.forms import PrimaryModelForm, PrimaryModelBulkEditForm, PrimaryModelFilterSetForm

from .choices import (
    AlertRepeatModeChoices,
    AlertTriggerUnitChoices,
    BundleFormatChoices,
    BundleStatusChoices,
    CertificateStatusChoices,
    LinkRelationChoices,
    SourceFormatChoices,
)
from .constants import ALERT_CHECK_INTERVAL_CHOICES
from .models import ArtifactGroup, Bundle, Certificate, CertificateAuthority, CSR, ExpiryAlertConfiguration, PrivateKey
from .services.csr import CSRGenerationError, generate_csr
from .services.encryption import encrypt_secret
from .services.importing import ArtifactImportError, choose_leaf, create_or_reuse_chain
from .services.ingest import apply_csr, apply_private_key, after_artifact_save
from .services.linker import ensure_automatic_bundle, resolve_certificate_parent
from .services.parser import ArtifactParseError, parse_blob


class CertificateForm(PrimaryModelForm):
    material = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 18, "autocomplete": "off"}))
    import_chain = forms.BooleanField(required=False, initial=False, label="Import certificate chain")
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    fieldsets = (
        FieldSet("name", "supersedes", "alert_trigger", "trigger_unit", "groups", "description", "tags", name="Certificate"),
        FieldSet("material", "import_chain", name="Certificate Material"),
    )
    class Meta:
        model = Certificate
        fields = ("name", "material", "supersedes", "alert_trigger", "trigger_unit", "owner", "groups", "description", "comments", "tags")
    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)
        if user is not None:
            self.fields["supersedes"].queryset = Certificate.objects.restrict(user, "view")
            self.fields["groups"].queryset = ArtifactGroup.objects.restrict(user, "view")
    def clean(self):
        super().clean()
        cleaned = self.cleaned_data
        material = cleaned.get("material")
        if not self.instance.pk and not material:
            self.add_error("material", "Certificate material is required when creating a certificate.")
            return cleaned
        if not material:
            if self.instance.pk:
                cleaned["material"] = self.instance.material
            return cleaned
        try:
            parsed = parse_blob(material.encode(), filename=self.instance.source_filename or "certificate.pem")
            if any(p.kind != "certificate" for p in parsed):
                raise ArtifactParseError("Certificate entry accepts certificate PEM blocks only.")
            leaf, chain = choose_leaf(parsed)
            if leaf is None:
                raise ArtifactParseError("No certificate was found.")
            if chain and not all(p.metadata.get("is_ca") for p in chain):
                raise ArtifactParseError("The certificate chain contains more than one non-CA certificate.")
        except (ArtifactParseError, ArtifactImportError) as exc:
            self.add_error("material", str(exc))
            return cleaned
        duplicate = Certificate.objects.filter(fingerprint_sha256=leaf.metadata["fingerprint_sha256"])
        if self.instance.pk:
            duplicate = duplicate.exclude(pk=self.instance.pk)
        if duplicate.exists():
            self.add_error("material", "This leaf certificate is already stored in NetBox Certificates.")
            return cleaned
        self._leaf = leaf
        self._chain = chain if cleaned.get("import_chain") else []
        self.instance.source_filename = self.instance.source_filename or "certificate.pem"
        self.instance.source_format = leaf.source_format
        self.instance.material = leaf.data.decode("ascii")
        self.instance.name = self.instance.name or leaf.name
        for field, value in leaf.metadata.items():
            setattr(self.instance, field, value)
        return cleaned
    def save(self, commit=True):
        obj = super().save(commit=commit)
        if commit:
            chain_objects = []
            if getattr(self, "_chain", None):
                chain_objects, _, _ = create_or_reuse_chain(
                    self._chain,
                    filename=self.instance.source_filename or "certificate.pem",
                    user=self.user,
                    owner=getattr(obj, "owner", None),
                    groups=obj.groups.all(),
                )
            after_artifact_save(obj)
            resolve_certificate_parent(obj)
            bundle = ensure_automatic_bundle(obj)
            if bundle and chain_objects:
                bundle.chain_certificates.add(*chain_objects)
                from .services.linker import sync_bundle_links
                sync_bundle_links(bundle)
        return obj


class CSRForm(PrimaryModelForm):
    material = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 18, "autocomplete": "off"}))
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    fieldsets = (FieldSet("name", "groups", "description", "tags", name="CSR"), FieldSet("material", name="CSR Material"))
    class Meta:
        model = CSR
        fields = ("name", "material", "owner", "groups", "description", "comments", "tags")
    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user is not None:
            self.fields["groups"].queryset = ArtifactGroup.objects.restrict(user, "view")
    def clean(self):
        super().clean()
        cleaned = self.cleaned_data
        material = cleaned.get("material")
        if not self.instance.pk and not material:
            self.add_error("material", "CSR material is required when creating a CSR.")
            return cleaned
        if not material and self.instance.pk:
            cleaned["material"] = self.instance.material
            return cleaned
        if material:
            try:
                apply_csr(self.instance, material.encode(), filename=self.instance.source_filename or "request.csr")
            except ArtifactParseError as exc:
                self.add_error("material", str(exc))
            else:
                duplicate = CSR.objects.filter(fingerprint_sha256=self.instance.fingerprint_sha256)
                if self.instance.pk:
                    duplicate = duplicate.exclude(pk=self.instance.pk)
                if duplicate.exists():
                    self.add_error("material", "This CSR is already stored in NetBox Certificates.")
        return cleaned
    def save(self, commit=True):
        obj = super().save(commit=commit)
        if commit:
            transaction.on_commit(lambda: after_artifact_save(obj))
        return obj


class PrivateKeyForm(PrimaryModelForm):
    key_material = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 18, "autocomplete": "off"}))
    input_password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}))
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    fieldsets = (FieldSet("name", "groups", "description", "tags", name="Private Key"), FieldSet("key_material", "input_password", name="Key Material"))
    class Meta:
        model = PrivateKey
        fields = ("name", "owner", "groups", "description", "comments", "tags")
    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user is not None:
            self.fields["groups"].queryset = ArtifactGroup.objects.restrict(user, "view")
    def clean(self):
        super().clean()
        cleaned = self.cleaned_data
        material = cleaned.get("key_material")
        if self.instance.pk is None and not material:
            self.add_error("key_material", "Private key material is required when creating a key.")
        if material:
            try:
                apply_private_key(self.instance, material.encode(), filename=self.instance.source_filename or "private.key", password=cleaned.get("input_password") or None)
            except ArtifactParseError as exc:
                self.add_error("key_material", str(exc))
            else:
                duplicate = PrivateKey.objects.filter(public_key_fingerprint=self.instance.public_key_fingerprint)
                if self.instance.pk:
                    duplicate = duplicate.exclude(pk=self.instance.pk)
                if duplicate.exists():
                    self.add_error("key_material", "A private key for this public key is already stored.")
        return cleaned
    def save(self, commit=True):
        obj = super().save(commit=commit)
        if commit:
            transaction.on_commit(lambda: after_artifact_save(obj))
        return obj


class BundleForm(PrimaryModelForm):
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    fieldsets = (FieldSet("groups", "description", "tags", name="Bundle Metadata"),)
    class Meta:
        model = Bundle
        fields = ("owner", "groups", "description", "comments", "tags")
    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user is not None:
            self.fields["groups"].queryset = ArtifactGroup.objects.restrict(user, "view")


class CertificateAuthorityForm(PrimaryModelForm):
    # The identity name is derived from the stored self-signed root CA and is
    # therefore intentionally read-only. Native NetBox owner/comments handling
    # remains available through the normal PrimaryModel form machinery.
    fieldsets = (
        FieldSet("description", "tags", name="Certificate Authority"),
    )

    class Meta:
        model = CertificateAuthority
        fields = ("owner", "description", "comments", "tags")


class ArtifactGroupForm(PrimaryModelForm):
    parent = DynamicModelChoiceField(
        queryset=ArtifactGroup.objects.all(),
        required=False,
        label="Parent Group",
    )
    members = forms.MultipleChoiceField(
        required=False,
        label="Members",
        widget=forms.SelectMultiple(attrs={"class": "form-select", "size": 14}),
    )
    fieldsets = (
        FieldSet("name", "parent", "description", "tags", name="Group"),
        FieldSet("members", name="Members"),
    )

    class Meta:
        model = ArtifactGroup
        fields = ("name", "parent", "owner", "description", "comments", "tags")

    def __init__(self, *args, user=None, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

        parent_qs = ArtifactGroup.objects.all()
        child_qs = ArtifactGroup.objects.all()
        certificate_qs = Certificate.objects.all()
        private_key_qs = PrivateKey.objects.all()
        csr_qs = CSR.objects.all()
        bundle_qs = Bundle.objects.all()

        if user is not None:
            parent_qs = ArtifactGroup.objects.restrict(user, "view")
            child_qs = ArtifactGroup.objects.restrict(user, "change")
            certificate_qs = Certificate.objects.restrict(user, "change")
            private_key_qs = PrivateKey.objects.restrict(user, "change")
            csr_qs = CSR.objects.restrict(user, "change")
            bundle_qs = Bundle.objects.restrict(user, "change")

        if self.instance.pk:
            excluded_parent_ids = {self.instance.pk, *self.instance.descendant_ids()}
            parent_qs = parent_qs.exclude(pk__in=excluded_parent_ids)

            # Parent choices are hierarchy-aware. A Group may only be moved beneath
            # a Group at its current level or above; deeper Groups are descendants
            # in the conceptual folder tree and must never be offered as parents.
            current_depth = len(self.instance.ancestor_ids())
            eligible_parent_ids = [
                candidate.pk
                for candidate in parent_qs
                if len(candidate.ancestor_ids()) <= current_depth
            ]
            parent_qs = parent_qs.filter(pk__in=eligible_parent_ids)

            excluded_child_ids = {self.instance.pk, *self.instance.ancestor_ids()}
            child_qs = child_qs.exclude(pk__in=excluded_child_ids)

        self.fields["parent"].queryset = parent_qs.order_by("name")
        self._member_querysets = {
            "group": child_qs.order_by("name"),
            "bundle": bundle_qs.order_by("name"),
            "certificate": certificate_qs.order_by("name"),
            "privatekey": private_key_qs.order_by("name"),
            "csr": csr_qs.order_by("name"),
        }
        self.fields["members"].choices = [
            ("Groups", [(f"group:{obj.pk}", obj.name) for obj in self._member_querysets["group"]]),
            ("Bundles", [(f"bundle:{obj.pk}", obj.name) for obj in self._member_querysets["bundle"]]),
            ("Certificates", [(f"certificate:{obj.pk}", obj.name) for obj in self._member_querysets["certificate"]]),
            ("Private Keys", [(f"privatekey:{obj.pk}", obj.name) for obj in self._member_querysets["privatekey"]]),
            ("CSRs", [(f"csr:{obj.pk}", obj.name) for obj in self._member_querysets["csr"]]),
        ]

        if self.instance.pk:
            initial = []
            initial.extend(f"group:{pk}" for pk in self._member_querysets["group"].filter(parent=self.instance).values_list("pk", flat=True))
            initial.extend(f"bundle:{pk}" for pk in self._member_querysets["bundle"].filter(groups=self.instance).values_list("pk", flat=True))
            initial.extend(f"certificate:{pk}" for pk in self._member_querysets["certificate"].filter(groups=self.instance).values_list("pk", flat=True))
            initial.extend(f"privatekey:{pk}" for pk in self._member_querysets["privatekey"].filter(groups=self.instance).values_list("pk", flat=True))
            initial.extend(f"csr:{pk}" for pk in self._member_querysets["csr"].filter(groups=self.instance).values_list("pk", flat=True))
            self.fields["members"].initial = initial

    def clean(self):
        super().clean()
        cleaned = self.cleaned_data
        parent = cleaned.get("parent")
        if self.instance.pk and parent is not None:
            if parent.pk == self.instance.pk or parent.pk in set(self.instance.descendant_ids()):
                self.add_error("parent", "A group cannot be nested below itself or one of its descendants.")
        selected = cleaned.get("members") or []
        selected_group_ids = set(self._selected_ids(selected, "group"))
        if self.instance.pk:
            ancestor_ids = set(self.instance.ancestor_ids())
            if selected_group_ids & ancestor_ids:
                self.add_error("members", "An ancestor Group cannot be moved below this Group.")
        if parent is not None:
            parent_ancestry = {parent.pk, *parent.ancestor_ids()}
            if selected_group_ids & parent_ancestry:
                self.add_error("members", "A Parent Group or one of its ancestors cannot also be a child member of this Group.")
        return cleaned

    @staticmethod
    def _selected_ids(values, kind):
        result = []
        prefix = f"{kind}:"
        for value in values:
            if value.startswith(prefix):
                raw = value[len(prefix):]
                if raw.isdigit():
                    result.append(int(raw))
        return result

    def save(self, commit=True):
        obj = super().save(commit=commit)
        if not commit:
            return obj

        selected = self.cleaned_data.get("members") or []
        with transaction.atomic():
            selected_groups = set(self._selected_ids(selected, "group"))
            mutable_groups = self._member_querysets["group"]
            for child in mutable_groups.filter(parent=obj).exclude(pk__in=selected_groups):
                child.parent = None
                child.save(update_fields=("parent", "last_updated"))
            for child in mutable_groups.filter(pk__in=selected_groups):
                if child.parent_id != obj.pk:
                    child.parent = obj
                    child.full_clean()
                    child.save(update_fields=("parent", "last_updated"))

            for kind, related_name in (
                ("bundle", "bundles"),
                ("certificate", "certificates"),
                ("privatekey", "private_keys"),
                ("csr", "csrs"),
            ):
                selected_ids = set(self._selected_ids(selected, kind))
                mutable_qs = self._member_querysets[kind]
                manager = getattr(obj, related_name)
                removable = list(mutable_qs.filter(groups=obj).exclude(pk__in=selected_ids))
                addable = list(mutable_qs.filter(pk__in=selected_ids))
                if removable:
                    manager.remove(*removable)
                if addable:
                    manager.add(*addable)
        return obj


BOOLEAN_FILTER_CHOICES = (("", "---------"), ("true", "Yes"), ("false", "No"))


class CompletePrimaryModelFilterForm(PrimaryModelFilterSetForm):
    """Common PrimaryModel fields exposed on every plugin object list filter."""

    id = forms.IntegerField(required=False, min_value=1, label="ID")
    owner = DynamicModelMultipleChoiceField(queryset=Owner.objects.all(), required=False, label="Owner")
    description = forms.CharField(required=False, label="Description contains")
    comments = forms.CharField(required=False, label="Comments contain")
    tags = forms.CharField(required=False, label="Tag name or slug contains")
    custom_field_data = forms.CharField(required=False, label="Custom field data contains")
    created = forms.DateTimeField(required=False, widget=forms.DateTimeInput(attrs={"type": "datetime-local"}), label="Created")
    created_after = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
        label="Created after",
    )
    created_before = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
        label="Created before",
    )
    last_updated = forms.DateTimeField(required=False, widget=forms.DateTimeInput(attrs={"type": "datetime-local"}), label="Last updated")
    last_updated_after = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
        label="Last updated after",
    )
    last_updated_before = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={"type": "datetime-local"}),
        label="Last updated before",
    )


class CertificateArtifactFilterForm(CompletePrimaryModelFilterForm):
    model = Certificate
    name = forms.CharField(required=False, label="Name contains")
    status = forms.MultipleChoiceField(choices=CertificateStatusChoices, required=False, label="Status")
    source_filename = forms.CharField(required=False, label="Source filename contains")
    source_format = forms.MultipleChoiceField(choices=SourceFormatChoices, required=False, label="Source Format")
    material = forms.CharField(required=False, label="Certificate material contains")
    fingerprint_sha256 = forms.CharField(required=False, label="SHA-256 fingerprint contains")
    public_key_fingerprint = forms.CharField(required=False, label="Public key fingerprint contains")
    serial_number = forms.CharField(required=False, label="Serial number contains")
    subject = forms.CharField(required=False, label="Subject contains")
    issuer = forms.CharField(required=False, label="Issuer contains")
    authority = DynamicModelMultipleChoiceField(queryset=CertificateAuthority.objects.all(), required=False, label="Certificate Authority")
    subject_alternative_names = forms.CharField(required=False, label="SAN contains")
    valid_from = forms.DateTimeField(required=False, widget=forms.DateTimeInput(attrs={"type": "datetime-local"}), label="Valid from")
    valid_from_after = forms.DateTimeField(required=False, widget=forms.DateTimeInput(attrs={"type": "datetime-local"}), label="Valid from after")
    valid_from_before = forms.DateTimeField(required=False, widget=forms.DateTimeInput(attrs={"type": "datetime-local"}), label="Valid from before")
    valid_to = forms.DateTimeField(required=False, widget=forms.DateTimeInput(attrs={"type": "datetime-local"}), label="Valid to")
    valid_to_after = forms.DateTimeField(required=False, widget=forms.DateTimeInput(attrs={"type": "datetime-local"}), label="Valid to after")
    valid_to_before = forms.DateTimeField(required=False, widget=forms.DateTimeInput(attrs={"type": "datetime-local"}), label="Valid to before")
    expires_in_days = forms.IntegerField(min_value=0, required=False, label="Expires within days")
    expired = forms.ChoiceField(choices=BOOLEAN_FILTER_CHOICES, required=False, label="Expired")
    signature_algorithm = forms.CharField(required=False, label="Signature algorithm contains")
    key_type = forms.CharField(required=False, label="Key Type")
    key_size = forms.IntegerField(required=False, min_value=1, label="Key Size")
    curve = forms.CharField(required=False, label="Curve")
    is_ca = forms.ChoiceField(choices=BOOLEAN_FILTER_CHOICES, required=False, label="CA Certificate")
    parent_certificate = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False, label="Parent Certificate")
    supersedes = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False, label="Supersedes")
    alert_trigger = forms.IntegerField(min_value=1, required=False, label="Alert Trigger")
    trigger_unit = forms.MultipleChoiceField(choices=AlertTriggerUnitChoices, required=False, label="Trigger Unit")
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    fieldsets = (
        FieldSet("q", "id", "name", name="Identity"),
        FieldSet("status", "source_filename", "source_format", "material", name="Source"),
        FieldSet("fingerprint_sha256", "public_key_fingerprint", "serial_number", name="Fingerprints & Serial"),
        FieldSet("subject", "issuer", "authority", "subject_alternative_names", name="X.509 Identity"),
        FieldSet("valid_from", "valid_from_after", "valid_from_before", "valid_to", "valid_to_after", "valid_to_before", "expires_in_days", "expired", name="Validity"),
        FieldSet("signature_algorithm", "key_type", "key_size", "curve", "is_ca", name="Cryptography"),
        FieldSet("parent_certificate", "supersedes", "alert_trigger", "trigger_unit", "groups", name="Relationships & Alerts"),
        FieldSet("owner", "tags", "description", "comments", "custom_field_data", name="NetBox Metadata"),
        FieldSet("created", "created_after", "created_before", "last_updated", "last_updated_after", "last_updated_before", name="Timestamps"),
    )


class CertificateAuthorityFilterForm(CompletePrimaryModelFilterForm):
    model = CertificateAuthority
    name = forms.CharField(required=False, label="Name contains")
    issuer_dn = forms.CharField(required=False, label="Issuer DN contains")
    certificates = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False, label="Certificates")
    fieldsets = (
        FieldSet("q", "id", "name", "issuer_dn", "certificates", name="Certificate Authority"),
        FieldSet("owner", "tags", "description", "comments", "custom_field_data", name="NetBox Metadata"),
        FieldSet("created", "created_after", "created_before", "last_updated", "last_updated_after", "last_updated_before", name="Timestamps"),
    )


class PrivateKeyArtifactFilterForm(CompletePrimaryModelFilterForm):
    model = PrivateKey
    name = forms.CharField(required=False, label="Name contains")
    source_filename = forms.CharField(required=False, label="Source filename contains")
    source_format = forms.MultipleChoiceField(choices=SourceFormatChoices, required=False, label="Source Format")
    has_encrypted_material = forms.ChoiceField(choices=BOOLEAN_FILTER_CHOICES, required=False, label="Stored key material")
    material_sha256 = forms.CharField(required=False, label="Material SHA-256 contains")
    public_key_fingerprint = forms.CharField(required=False, label="Public key fingerprint contains")
    key_type = forms.CharField(required=False, label="Key Type")
    key_size = forms.IntegerField(required=False, min_value=1, label="Key Size")
    encrypted_on_import = forms.ChoiceField(choices=BOOLEAN_FILTER_CHOICES, required=False, label="Encrypted on import")
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    fieldsets = (
        FieldSet("q", "id", "name", name="Identity"),
        FieldSet("source_filename", "source_format", "has_encrypted_material", "encrypted_on_import", name="Source & Storage"),
        FieldSet("material_sha256", "public_key_fingerprint", "key_type", "key_size", name="Cryptography"),
        FieldSet("groups", "owner", "tags", "description", "comments", "custom_field_data", name="NetBox Metadata"),
        FieldSet("created", "created_after", "created_before", "last_updated", "last_updated_after", "last_updated_before", name="Timestamps"),
    )


class CSRArtifactFilterForm(CompletePrimaryModelFilterForm):
    model = CSR
    name = forms.CharField(required=False, label="Name contains")
    source_filename = forms.CharField(required=False, label="Source filename contains")
    source_format = forms.MultipleChoiceField(choices=SourceFormatChoices, required=False, label="Source Format")
    material = forms.CharField(required=False, label="CSR material contains")
    fingerprint_sha256 = forms.CharField(required=False, label="SHA-256 fingerprint contains")
    public_key_fingerprint = forms.CharField(required=False, label="Public key fingerprint contains")
    subject = forms.CharField(required=False, label="Subject contains")
    subject_alternative_names = forms.CharField(required=False, label="SAN contains")
    signature_algorithm = forms.CharField(required=False, label="Signature algorithm contains")
    key_type = forms.CharField(required=False, label="Key Type")
    key_size = forms.IntegerField(required=False, min_value=1, label="Key Size")
    curve = forms.CharField(required=False, label="Curve")
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    fieldsets = (
        FieldSet("q", "id", "name", name="Identity"),
        FieldSet("source_filename", "source_format", "material", name="Source"),
        FieldSet("fingerprint_sha256", "public_key_fingerprint", name="Fingerprints"),
        FieldSet("subject", "subject_alternative_names", name="Requested Identity"),
        FieldSet("signature_algorithm", "key_type", "key_size", "curve", name="Cryptography"),
        FieldSet("groups", "owner", "tags", "description", "comments", "custom_field_data", name="NetBox Metadata"),
        FieldSet("created", "created_after", "created_before", "last_updated", "last_updated_after", "last_updated_before", name="Timestamps"),
    )


class BundleArtifactFilterForm(CompletePrimaryModelFilterForm):
    model = Bundle
    name = forms.CharField(required=False, label="Name contains")
    identity_fingerprint = forms.CharField(required=False, label="Identity fingerprint contains")
    source_filename = forms.CharField(required=False, label="Source filename contains")
    archive_format = forms.MultipleChoiceField(choices=BundleFormatChoices, required=False, label="Archive Format")
    status = forms.MultipleChoiceField(choices=BundleStatusChoices, required=False, label="Status")
    has_encrypted_archive = forms.ChoiceField(choices=BOOLEAN_FILTER_CHOICES, required=False, label="Preserved archive")
    import_report = forms.CharField(required=False, label="Import report contains")
    certificate = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False, label="Certificate")
    private_key = DynamicModelMultipleChoiceField(queryset=PrivateKey.objects.all(), required=False, label="Private Key")
    csr = DynamicModelMultipleChoiceField(queryset=CSR.objects.all(), required=False, label="CSR")
    chain_certificates = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False, label="Chain Certificates")
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    fieldsets = (
        FieldSet("q", "id", "name", "identity_fingerprint", name="Identity"),
        FieldSet("source_filename", "archive_format", "status", "has_encrypted_archive", "import_report", name="Archive & Import"),
        FieldSet("certificate", "private_key", "csr", "chain_certificates", "groups", name="Members & Relationships"),
        FieldSet("owner", "tags", "description", "comments", "custom_field_data", name="NetBox Metadata"),
        FieldSet("created", "created_after", "created_before", "last_updated", "last_updated_after", "last_updated_before", name="Timestamps"),
    )


class ArtifactGroupFilterForm(CompletePrimaryModelFilterForm):
    model = ArtifactGroup
    name = forms.CharField(required=False, label="Name contains")
    parent = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Parent Group")
    children = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Child Groups")
    certificates = DynamicModelMultipleChoiceField(queryset=Certificate.objects.all(), required=False, label="Certificates")
    private_keys = DynamicModelMultipleChoiceField(queryset=PrivateKey.objects.all(), required=False, label="Private Keys")
    csrs = DynamicModelMultipleChoiceField(queryset=CSR.objects.all(), required=False, label="CSRs")
    bundles = DynamicModelMultipleChoiceField(queryset=Bundle.objects.all(), required=False, label="Bundles")
    fieldsets = (
        FieldSet("q", "id", "name", "parent", "children", name="Hierarchy"),
        FieldSet("certificates", "private_keys", "csrs", "bundles", name="Members"),
        FieldSet("owner", "tags", "description", "comments", "custom_field_data", name="NetBox Metadata"),
        FieldSet("created", "created_after", "created_before", "last_updated", "last_updated_after", "last_updated_before", name="Timestamps"),
    )


class CertificateBulkEditForm(PrimaryModelBulkEditForm):
    alert_trigger = forms.IntegerField(min_value=1, required=False, label="Alert Trigger")
    trigger_unit = forms.ChoiceField(choices=AlertTriggerUnitChoices, required=False, label="Trigger Unit")
    owner = DynamicModelChoiceField(queryset=Owner.objects.all(), required=False)
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    model = Certificate
    fieldsets = (FieldSet("alert_trigger", "trigger_unit", "owner", "groups", "description", "comments", "tags", name="Bulk-editable fields"),)
    nullable_fields = ("alert_trigger", "trigger_unit", "owner", "groups", "description", "comments")


class PrivateKeyBulkEditForm(PrimaryModelBulkEditForm):
    owner = DynamicModelChoiceField(queryset=Owner.objects.all(), required=False)
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    model = PrivateKey
    fieldsets = (FieldSet("owner", "groups", "description", "comments", "tags", name="Bulk-editable fields"),)
    nullable_fields = ("owner", "groups", "description", "comments")


class CSRBulkEditForm(PrimaryModelBulkEditForm):
    owner = DynamicModelChoiceField(queryset=Owner.objects.all(), required=False)
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    model = CSR
    fieldsets = (FieldSet("owner", "groups", "description", "comments", "tags", name="Bulk-editable fields"),)
    nullable_fields = ("owner", "groups", "description", "comments")


class BundleBulkEditForm(PrimaryModelBulkEditForm):
    owner = DynamicModelChoiceField(queryset=Owner.objects.all(), required=False)
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    model = Bundle
    fieldsets = (FieldSet("owner", "groups", "description", "comments", "tags", name="Bulk-editable fields"),)
    nullable_fields = ("owner", "groups", "description", "comments")


class ArtifactGroupBulkEditForm(PrimaryModelBulkEditForm):
    parent = DynamicModelChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Parent Group")
    owner = DynamicModelChoiceField(queryset=Owner.objects.all(), required=False)
    model = ArtifactGroup
    fieldsets = (FieldSet("parent", "owner", "description", "comments", "tags", name="Bulk-editable fields"),)
    nullable_fields = ("parent", "owner", "description", "comments")


class MultipleFileInput(forms.ClearableFileInput):
    allow_multiple_selected = True


class MultipleFileField(forms.FileField):
    widget = MultipleFileInput
    def clean(self, data, initial=None):
        single_clean = super().clean
        if isinstance(data, (list, tuple)):
            return [single_clean(item, initial) for item in data]
        return [single_clean(data, initial)]


class UnifiedImportForm(forms.Form):
    files = MultipleFileField(label="Objects or archive")
    password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False), label="Object Password")
    archive_password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False), label="Archive Password")
    import_chain = forms.BooleanField(required=False, initial=True, label="Import certificate chain")
    preserve_archive = forms.BooleanField(required=False, initial=True, label="Preserve original Bundle archive")
    owner = forms.ModelChoiceField(queryset=Owner.objects.none(), required=False)
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    description = forms.CharField(required=False, max_length=200)
    comments = forms.CharField(required=False, widget=forms.Textarea(attrs={"rows": 3}))
    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user:
            self.fields["owner"].queryset = Owner.objects.filter(users=user)
            self.fields["groups"].queryset = ArtifactGroup.objects.restrict(user, "view")


class BundleExportForm(forms.Form):
    archive_format = forms.ChoiceField(choices=(("zip", "ZIP"), ("tar", "TAR")), initial="zip")
    export_pfx = forms.BooleanField(required=False, initial=False, label="Export as PFX")
    include_chain = forms.BooleanField(required=False, initial=False, label="Include certificate chain")
    pfx_password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}))
    pfx_password_confirm = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}))
    def clean(self):
        cleaned = super().clean()
        if cleaned.get("export_pfx"):
            password = cleaned.get("pfx_password") or ""
            if not password:
                self.add_error("pfx_password", "A password is required for PFX export.")
            elif password != (cleaned.get("pfx_password_confirm") or ""):
                self.add_error("pfx_password_confirm", "Passwords do not match.")
        return cleaned


class CSRGenerateForm(forms.Form):
    name = forms.CharField(max_length=200, required=False)
    owner = forms.ModelChoiceField(queryset=Owner.objects.none(), required=False)
    groups = DynamicModelMultipleChoiceField(queryset=ArtifactGroup.objects.all(), required=False, label="Groups")
    common_name = forms.CharField(max_length=255, label="Common Name (CN)")
    sans = forms.CharField(required=False, widget=forms.HiddenInput())
    country = forms.CharField(max_length=2, required=False, label="Country (C)")
    state = forms.CharField(max_length=128, required=False, label="State / Province (ST)")
    locality = forms.CharField(max_length=128, required=False, label="Locality (L)")
    organization = forms.CharField(max_length=128, required=False, label="Organization (O)")
    organizational_unit = forms.CharField(max_length=128, required=False, label="Organizational Unit (OU)")
    street_address = forms.CharField(max_length=255, required=False)
    postal_code = forms.CharField(max_length=64, required=False)
    subject_serial_number = forms.CharField(max_length=128, required=False, label="Subject Serial Number")
    email = forms.EmailField(required=False)
    key_algorithm = forms.ChoiceField(choices=(("rsa", "RSA"), ("ec", "ECDSA"), ("ed25519", "Ed25519"), ("ed448", "Ed448")), initial="rsa")
    rsa_bits = forms.ChoiceField(choices=((2048, "2048"), (3072, "3072"), (4096, "4096"), (8192, "8192")), initial=3072)
    ec_curve = forms.ChoiceField(choices=(("secp256r1", "P-256"), ("secp384r1", "P-384"), ("secp521r1", "P-521")), initial="secp256r1")
    signature_hash = forms.ChoiceField(choices=(("sha256", "SHA-256"), ("sha384", "SHA-384"), ("sha512", "SHA-512")), initial="sha256")
    rsa_signature = forms.ChoiceField(choices=(("pkcs1v15", "PKCS#1 v1.5"), ("pss", "RSA-PSS")), initial="pkcs1v15")
    ku_digital_signature = forms.BooleanField(required=False, initial=True, label="Digital Signature")
    ku_content_commitment = forms.BooleanField(required=False, label="Content Commitment")
    ku_key_encipherment = forms.BooleanField(required=False, initial=True, label="Key Encipherment")
    ku_data_encipherment = forms.BooleanField(required=False, label="Data Encipherment")
    ku_key_agreement = forms.BooleanField(required=False, label="Key Agreement")
    ku_key_cert_sign = forms.BooleanField(required=False, label="Certificate Signing")
    ku_crl_sign = forms.BooleanField(required=False, label="CRL Signing")
    eku_server_auth = forms.BooleanField(required=False, initial=True, label="TLS Web Server Authentication")
    eku_client_auth = forms.BooleanField(required=False, label="TLS Web Client Authentication")
    eku_code_signing = forms.BooleanField(required=False, label="Code Signing")
    eku_email_protection = forms.BooleanField(required=False, label="Email Protection")
    eku_time_stamping = forms.BooleanField(required=False, label="Time Stamping")
    eku_ocsp_signing = forms.BooleanField(required=False, label="OCSP Signing")
    request_ca = forms.BooleanField(required=False, label="Request CA certificate")
    path_length = forms.IntegerField(required=False, min_value=0, label="CA path length constraint")
    fieldsets = (
        FieldSet("name", "owner", "groups", name="NetBox Metadata"),
        FieldSet("common_name", "organization", "organizational_unit", "country", "state", "locality", "street_address", "postal_code", "subject_serial_number", "email", name="Subject"),
        FieldSet("sans", name="Subject Alternative Names"),
        FieldSet("key_algorithm", "rsa_bits", "ec_curve", "signature_hash", "rsa_signature", name="Private Key & Signature"),
        FieldSet("ku_digital_signature", "ku_content_commitment", "ku_key_encipherment", "ku_data_encipherment", "ku_key_agreement", "ku_key_cert_sign", "ku_crl_sign", "eku_server_auth", "eku_client_auth", "eku_code_signing", "eku_email_protection", "eku_time_stamping", "eku_ocsp_signing", "request_ca", "path_length", name="Requested X.509 Extensions"),
    )
    def __init__(self, *args, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if user:
            self.fields["owner"].queryset = Owner.objects.filter(users=user)
            self.fields["groups"].queryset = ArtifactGroup.objects.restrict(user, "view")
        for name in ("ku_digital_signature", "ku_content_commitment", "ku_key_encipherment", "ku_data_encipherment", "ku_key_agreement", "ku_key_cert_sign", "ku_crl_sign", "eku_server_auth", "eku_client_auth", "eku_code_signing", "eku_email_protection", "eku_time_stamping", "eku_ocsp_signing", "request_ca"):
            self.fields[name].widget.attrs["class"] = "form-check-input"
    def clean_sans(self):
        value = self.cleaned_data.get("sans", "")
        entries = []
        for raw in value.splitlines():
            raw = raw.strip()
            if not raw:
                continue
            prefix, sep, san_value = raw.partition(":")
            if not sep or prefix.upper() not in {"DNS", "IP", "EMAIL", "URI"} or not san_value.strip():
                raise ValidationError("Each SAN must have a type (DNS, IP, EMAIL, or URI) and a value.")
            entries.append(f"{prefix.upper()}:{san_value.strip()}")
        return "\n".join(entries)


class ExpiryAlertConfigurationForm(forms.ModelForm):
    smtp_password = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}), label="SMTP password")
    webhook_url = forms.URLField(required=False, label="Webhook URL")
    webhook_bearer_token = forms.CharField(required=False, widget=forms.PasswordInput(render_value=False, attrs={"autocomplete": "new-password"}), label="Webhook bearer token")
    check_interval_minutes = forms.TypedChoiceField(choices=ALERT_CHECK_INTERVAL_CHOICES, coerce=int, label="Check interval")
    alert_repeat_mode = forms.ChoiceField(choices=AlertRepeatModeChoices, label="Repeat behavior")
    class Meta:
        model = ExpiryAlertConfiguration
        fields = (
            "check_interval_minutes", "alert_on_expired_certificates", "alert_repeat_mode",
            "email_enabled", "smtp_host", "smtp_port", "smtp_username", "smtp_use_tls", "smtp_use_ssl",
            "email_from_address", "email_recipients", "include_superusers",
            "webhook_enabled", "webhook_allow_http", "webhook_ignore_tls_verification",
        )
        labels = {
            "email_enabled": "Enable email",
            "smtp_host": "SMTP host",
            "smtp_port": "SMTP port",
            "smtp_username": "SMTP username",
            "smtp_use_tls": "Use STARTTLS",
            "smtp_use_ssl": "Use implicit SSL/TLS",
            "email_from_address": "From address",
            "email_recipients": "Recipients",
            "include_superusers": "Include active NetBox superusers",
            "webhook_enabled": "Enable webhook",
            "webhook_allow_http": "Allow insecure HTTP webhook",
            "webhook_ignore_tls_verification": "Ignore TLS certificate verification",
        }
        widgets = {"email_recipients": forms.Textarea(attrs={"rows": 3, "placeholder": "admin@example.com\nops@example.com"})}
    def __init__(self, *args, require_email=False, require_webhook=False, **kwargs):
        self.require_email = require_email
        self.require_webhook = require_webhook
        super().__init__(*args, **kwargs)
        if getattr(self.instance, "smtp_password_encrypted", None):
            self.fields["smtp_password"].widget.attrs["placeholder"] = "Configured — leave blank to keep"
        if getattr(self.instance, "webhook_url_encrypted", None):
            self.fields["webhook_url"].widget.attrs["placeholder"] = "Configured — enter a new URL to replace"
        if getattr(self.instance, "webhook_bearer_token_encrypted", None):
            self.fields["webhook_bearer_token"].widget.attrs["placeholder"] = "Configured — leave blank to keep"
    def clean(self):
        cleaned = super().clean()
        email_needed = cleaned.get("email_enabled") or self.require_email
        webhook_needed = cleaned.get("webhook_enabled") or self.require_webhook
        if cleaned.get("smtp_use_tls") and cleaned.get("smtp_use_ssl"):
            self.add_error("smtp_use_ssl", "STARTTLS and implicit SSL/TLS cannot both be enabled.")
        if email_needed:
            if not cleaned.get("smtp_host"): self.add_error("smtp_host", "SMTP host is required.")
            if not cleaned.get("smtp_port"): self.add_error("smtp_port", "SMTP port is required.")
            if not cleaned.get("email_from_address"): self.add_error("email_from_address", "From address is required.")
            if not cleaned.get("include_superusers") and not cleaned.get("email_recipients", "").strip():
                self.add_error("email_recipients", "Add at least one recipient or enable NetBox superuser recipients.")
        existing_url = bool(getattr(self.instance, "webhook_url_encrypted", None))
        if webhook_needed and not cleaned.get("webhook_url") and not existing_url:
            self.add_error("webhook_url", "Webhook URL is required.")
        url = cleaned.get("webhook_url")
        if url and url.lower().startswith("http://") and not cleaned.get("webhook_allow_http"):
            self.add_error("webhook_url", "HTTP webhooks require 'Allow insecure HTTP webhook'.")
        return cleaned
    def save(self, commit=True):
        obj = super().save(commit=False)
        if self.cleaned_data.get("smtp_password"):
            obj.smtp_password_encrypted = encrypt_secret(self.cleaned_data["smtp_password"])
        if self.cleaned_data.get("webhook_url"):
            obj.webhook_url_encrypted = encrypt_secret(self.cleaned_data["webhook_url"])
        if self.cleaned_data.get("webhook_bearer_token"):
            obj.webhook_bearer_token_encrypted = encrypt_secret(self.cleaned_data["webhook_bearer_token"])
        if commit:
            obj.save()
        return obj


class ArtifactLinkTypeForm(forms.Form):
    target_type = forms.ModelChoiceField(queryset=ObjectType.objects.filter(public=True), label="NetBox object type")


class ArtifactLinkForm(forms.Form):
    target_type = forms.IntegerField(widget=forms.HiddenInput())
    target = DynamicModelChoiceField(queryset=Certificate.objects.none(), required=True)
    relation = forms.ChoiceField(choices=LinkRelationChoices, required=True, initial="related")
    note = forms.CharField(required=False, max_length=500)
    def __init__(self, *args, target_type=None, user=None, **kwargs):
        super().__init__(*args, **kwargs)
        if target_type is not None:
            self.fields["target_type"].initial = target_type.pk
            model = target_type.model_class()
            manager = getattr(model, "objects", None)
            if manager is not None:
                queryset = manager.all()
                if user is not None and hasattr(queryset, "restrict"):
                    queryset = queryset.restrict(user, "view")
                self.fields["target"].queryset = queryset
