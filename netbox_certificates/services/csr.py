from __future__ import annotations

from ipaddress import ip_address
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, ed448, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CSRGenerationError(ValueError):
    pass


HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}
CURVES = {"secp256r1": ec.SECP256R1, "secp384r1": ec.SECP384R1, "secp521r1": ec.SECP521R1}
EKUS = {
    "server_auth": ExtendedKeyUsageOID.SERVER_AUTH,
    "client_auth": ExtendedKeyUsageOID.CLIENT_AUTH,
    "code_signing": ExtendedKeyUsageOID.CODE_SIGNING,
    "email_protection": ExtendedKeyUsageOID.EMAIL_PROTECTION,
    "time_stamping": ExtendedKeyUsageOID.TIME_STAMPING,
    "ocsp_signing": ExtendedKeyUsageOID.OCSP_SIGNING,
}


def _parse_san(entry: str):
    entry = entry.strip()
    if not entry:
        return None
    prefix, sep, value = entry.partition(":")
    if sep and prefix.upper() in {"DNS", "IP", "EMAIL", "URI"}:
        kind = prefix.upper()
        value = value.strip()
    else:
        value = entry
        try:
            return x509.IPAddress(ip_address(value))
        except ValueError:
            kind = "DNS"
    if not value:
        raise CSRGenerationError(f"Invalid SAN entry: {entry!r}")
    if kind == "IP":
        try:
            return x509.IPAddress(ip_address(value))
        except ValueError as exc:
            raise CSRGenerationError(f"Invalid IP SAN: {value}") from exc
    if kind == "EMAIL":
        return x509.RFC822Name(value)
    if kind == "URI":
        return x509.UniformResourceIdentifier(value)
    return x509.DNSName(value)


def generate_csr(*, common_name, sans=None, key_algorithm="rsa", rsa_bits=3072, ec_curve="secp256r1", signature_hash="sha256", rsa_signature="pkcs1v15", country="", state="", locality="", organization="", organizational_unit="", street_address="", postal_code="", subject_serial_number="", email="", key_usages=None, extended_key_usages=None, request_ca=False, path_length=None):
    if not common_name:
        raise CSRGenerationError("Common Name is required.")
    if key_algorithm == "rsa":
        rsa_bits = int(rsa_bits)
        if rsa_bits not in (2048, 3072, 4096, 8192):
            raise CSRGenerationError("RSA key size must be 2048, 3072, 4096, or 8192 bits.")
        key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
    elif key_algorithm == "ec":
        curve_type = CURVES.get(ec_curve)
        if curve_type is None:
            raise CSRGenerationError("Unsupported EC curve.")
        key = ec.generate_private_key(curve_type())
    elif key_algorithm == "ed25519":
        key = ed25519.Ed25519PrivateKey.generate()
    elif key_algorithm == "ed448":
        key = ed448.Ed448PrivateKey.generate()
    else:
        raise CSRGenerationError("Unsupported key algorithm.")

    attrs = [(NameOID.COMMON_NAME, common_name)]
    optional = (
        (NameOID.COUNTRY_NAME, country),
        (NameOID.STATE_OR_PROVINCE_NAME, state),
        (NameOID.LOCALITY_NAME, locality),
        (NameOID.ORGANIZATION_NAME, organization),
        (NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit),
        (NameOID.STREET_ADDRESS, street_address),
        (NameOID.POSTAL_CODE, postal_code),
        (NameOID.SERIAL_NUMBER, subject_serial_number),
        (NameOID.EMAIL_ADDRESS, email),
    )
    attrs.extend((oid, value) for oid, value in optional if value)
    subject = x509.Name([x509.NameAttribute(oid, value) for oid, value in attrs])
    builder = x509.CertificateSigningRequestBuilder().subject_name(subject)

    general_names = []
    for entry in sans or []:
        parsed = _parse_san(entry)
        if parsed is not None and parsed not in general_names:
            general_names.append(parsed)
    if general_names:
        builder = builder.add_extension(x509.SubjectAlternativeName(general_names), critical=False)

    key_usages = set(key_usages or [])
    if key_usages:
        key_agreement = "key_agreement" in key_usages
        usage = x509.KeyUsage(
            digital_signature="digital_signature" in key_usages,
            content_commitment="content_commitment" in key_usages,
            key_encipherment="key_encipherment" in key_usages,
            data_encipherment="data_encipherment" in key_usages,
            key_agreement=key_agreement,
            key_cert_sign="key_cert_sign" in key_usages,
            crl_sign="crl_sign" in key_usages,
            encipher_only=False if key_agreement else None,
            decipher_only=False if key_agreement else None,
        )
        builder = builder.add_extension(usage, critical=True)
    eku_oids = [EKUS[item] for item in (extended_key_usages or []) if item in EKUS]
    if eku_oids:
        builder = builder.add_extension(x509.ExtendedKeyUsage(eku_oids), critical=False)
    if request_ca:
        if path_length in ("", None):
            path_length = None
        else:
            path_length = int(path_length)
            if path_length < 0:
                raise CSRGenerationError("CA path length cannot be negative.")
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)

    if isinstance(key, (ed25519.Ed25519PrivateKey, ed448.Ed448PrivateKey)):
        csr = builder.sign(key, None)
    else:
        hash_type = HASHES.get(signature_hash)
        if hash_type is None:
            raise CSRGenerationError("Unsupported signature hash algorithm.")
        kwargs = {}
        if isinstance(key, rsa.RSAPrivateKey) and rsa_signature == "pss":
            kwargs["rsa_padding"] = padding.PSS(mgf=padding.MGF1(hash_type()), salt_length=padding.PSS.DIGEST_LENGTH)
        elif isinstance(key, rsa.RSAPrivateKey) and rsa_signature != "pkcs1v15":
            raise CSRGenerationError("Unsupported RSA signature mode.")
        csr = builder.sign(key, hash_type(), **kwargs)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return key_pem, csr.public_bytes(serialization.Encoding.PEM)
