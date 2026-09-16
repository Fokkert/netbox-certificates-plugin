"""One transaction and permission contract for UI/API CSR generation."""
from django.core.exceptions import PermissionDenied
from django.db import transaction

from ..models import Bundle, Certificate, CSR, PrivateKey
from ..permissions import object_allowed, require_action_permission
from .csr import generate_csr
from .encryption import decrypt_private_key
from .importing import _create, _check_created_permission
from .ingest import after_artifact_save
from .linker import find_matching_bundle
from .parser import parse_blob


@transaction.atomic
def save_generated_csr(data, user):
    require_action_permission(CSR, user, "add")
    key = data.get("existing_private_key")
    if key is not None:
        if not object_allowed(user, key, "use"):
            raise PermissionDenied("You do not have permission to sign with this private key.")
        key_pem = decrypt_private_key(key.encrypted_material)
    else:
        require_action_permission(PrivateKey, user, "add")
        key_pem = None
    options = {name: data.get(name) for name in (
        "common_name", "key_algorithm", "rsa_bits", "ec_curve", "signature_hash", "rsa_signature",
        "country", "state", "locality", "organization", "organizational_unit", "street_address",
        "postal_code", "subject_serial_number", "email", "request_ca", "path_length",
    )}
    generated_key, csr_pem = generate_csr(
        **options, private_key_pem=key_pem, sans=data.get("sans", "").splitlines(),
        key_usages=[name[3:] for name, value in data.items() if name.startswith("ku_") and value],
        extended_key_usages=[name[4:] for name, value in data.items() if name.startswith("eku_") and value],
    )
    new_key = key is None
    if new_key:
        parsed = parse_blob(generated_key, filename="generated.key")[0]
        parsed.name = ((data.get("name") or data["common_name"])[:196] + " key")
        key = _create(parsed, "generated.key", owner=data.get("owner"))
    parsed = parse_blob(csr_pem, filename="generated.csr")[0]
    parsed.name = data.get("name") or data["common_name"]
    csr = _create(parsed, "generated.csr", owner=data.get("owner"))
    fingerprint = csr.public_key_fingerprint
    for model in (Certificate, CSR, PrivateKey):
        for peer in model.objects.filter(public_key_fingerprint=fingerprint):
            if not object_allowed(user, peer):
                raise PermissionDenied("Matching material is not visible to your account.")
    bundle = find_matching_bundle(fingerprint)
    if bundle is not None:
        if not object_allowed(user, bundle, "change"):
            raise PermissionDenied("Change permission is required to update the matching Bundle.")
    else:
        require_action_permission(Bundle, user, "add")
    if data.get("groups"):
        csr.groups.add(*data["groups"])
        if new_key:
            key.groups.add(*data["groups"])
    _check_created_permission(user, csr)
    if new_key:
        _check_created_permission(user, key)
    if new_key:
        after_artifact_save(key)
    after_artifact_save(csr)
    if bundle is None:
        bundle = Bundle.objects.filter(identity_fingerprint=fingerprint).first()
        if bundle is not None:
            _check_created_permission(user, bundle)
    return csr, key
