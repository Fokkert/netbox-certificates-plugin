from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Literal

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7

from .status import calculate_certificate_status

ArtifactKind = Literal["certificate", "private_key", "csr"]
PEM_BLOCK_RE = re.compile(rb"-----BEGIN ([A-Z0-9 ][A-Z0-9 -]*)-----.*?-----END \1-----", re.DOTALL)


class ArtifactParseError(ValueError):
    pass


@dataclass
class ParsedArtifact:
    kind: ArtifactKind
    data: bytes
    source_format: str
    name: str
    metadata: dict = field(default_factory=dict)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def public_key_fingerprint(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256_hex(der)


def _key_metadata(public_key) -> dict:
    name = public_key.__class__.__name__.lower()
    if "rsa" in name:
        return {"key_type": "RSA", "key_size": getattr(public_key, "key_size", None), "curve": ""}
    if "ellipticcurve" in name or "ec" in name:
        curve = getattr(getattr(public_key, "curve", None), "name", "")
        return {"key_type": "EC", "key_size": getattr(public_key, "key_size", None), "curve": curve}
    if "ed25519" in name:
        return {"key_type": "Ed25519", "key_size": None, "curve": ""}
    if "ed448" in name:
        return {"key_type": "Ed448", "key_size": None, "curve": ""}
    return {"key_type": public_key.__class__.__name__, "key_size": getattr(public_key, "key_size", None), "curve": ""}


def _name_from_x509_name(name: x509.Name) -> str:
    attrs = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    if attrs:
        return attrs[0].value
    return name.rfc4514_string() or "Unnamed"


def _sans(exts) -> list[str]:
    try:
        san = exts.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    values = []
    for value in san:
        if isinstance(value, x509.DNSName):
            values.append(f"DNS:{value.value}")
        elif isinstance(value, x509.IPAddress):
            values.append(f"IP:{value.value}")
        elif isinstance(value, x509.UniformResourceIdentifier):
            values.append(f"URI:{value.value}")
        elif isinstance(value, x509.RFC822Name):
            values.append(f"EMAIL:{value.value}")
        else:
            values.append(str(value.value))
    return values


def _certificate_parsed(cert: x509.Certificate, source_format: str) -> ParsedArtifact:
    pem = cert.public_bytes(serialization.Encoding.PEM)
    pub = cert.public_key()
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca = bool(bc.ca)
    except x509.ExtensionNotFound:
        is_ca = False
    nvb = cert.not_valid_before_utc
    nva = cert.not_valid_after_utc
    sig_alg = getattr(cert.signature_hash_algorithm, "name", "") if cert.signature_hash_algorithm else ""
    meta = {
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
        "public_key_fingerprint": public_key_fingerprint(pub),
        "serial_number": format(cert.serial_number, "X"),
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "subject_alternative_names": _sans(cert.extensions),
        "valid_from": nvb,
        "valid_to": nva,
        "signature_algorithm": sig_alg,
        "is_ca": is_ca,
        "status": calculate_certificate_status(nvb, nva),
        **_key_metadata(pub),
    }
    return ParsedArtifact("certificate", pem, source_format, _name_from_x509_name(cert.subject), meta)


def _csr_parsed(csr: x509.CertificateSigningRequest, source_format: str) -> ParsedArtifact:
    if not csr.is_signature_valid:
        raise ArtifactParseError("The CSR is structurally readable, but its cryptographic signature is invalid.")
    pem = csr.public_bytes(serialization.Encoding.PEM)
    pub = csr.public_key()
    sig_alg = getattr(csr.signature_hash_algorithm, "name", "") if csr.signature_hash_algorithm else ""
    meta = {
        "fingerprint_sha256": sha256_hex(csr.public_bytes(serialization.Encoding.DER)),
        "public_key_fingerprint": public_key_fingerprint(pub),
        "subject": csr.subject.rfc4514_string(),
        "subject_alternative_names": _sans(csr.extensions),
        "signature_algorithm": sig_alg,
        **_key_metadata(pub),
    }
    return ParsedArtifact("csr", pem, source_format, _name_from_x509_name(csr.subject), meta)


def _private_key_parsed(key, source_format: str, encrypted_on_import: bool) -> ParsedArtifact:
    normalized = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub = key.public_key()
    meta = {
        "material_sha256": sha256_hex(normalized),
        "public_key_fingerprint": public_key_fingerprint(pub),
        "encrypted_on_import": encrypted_on_import,
        **_key_metadata(pub),
    }
    label = meta["public_key_fingerprint"][:12]
    return ParsedArtifact("private_key", normalized, source_format, f"Private Key {label}", meta)


def parse_blob(data: bytes, password: str | bytes | None = None, filename: str = "") -> list[ParsedArtifact]:
    if not data:
        raise ArtifactParseError("The uploaded file is empty.")
    password_b = password.encode() if isinstance(password, str) else password
    lower_name = filename.lower()

    if b"-----BEGIN " in data:
        blocks = [m.group(0) for m in PEM_BLOCK_RE.finditer(data)]
        if not blocks:
            raise ArtifactParseError("PEM markers were found, but no complete PEM block could be parsed.")
        if data.count(b"-----BEGIN ") != len(blocks):
            raise ArtifactParseError("The PEM input contains an incomplete or malformed PEM block.")
        results = []
        errors = []
        for block in blocks:
            header = block.splitlines()[0].decode("ascii", "replace")
            try:
                if "CERTIFICATE REQUEST" in header or "NEW CERTIFICATE REQUEST" in header:
                    results.append(_csr_parsed(x509.load_pem_x509_csr(block), "pem"))
                elif header == "-----BEGIN CERTIFICATE-----":
                    results.append(_certificate_parsed(x509.load_pem_x509_certificate(block), "pem"))
                elif "PKCS7" in header or "CMS" in header:
                    certs = pkcs7.load_pem_pkcs7_certificates(block)
                    if not certs:
                        raise ArtifactParseError("The PKCS#7/CMS PEM block contains no certificates.")
                    results.extend(_certificate_parsed(cert, "pkcs7") for cert in certs)
                elif "PRIVATE KEY" in header:
                    encrypted_input = "ENCRYPTED PRIVATE KEY" in header
                    try:
                        key = serialization.load_pem_private_key(block, password=password_b)
                    except TypeError as exc:
                        msg = str(exc).lower()
                        if password_b is None and ("password was not given" in msg or "private key is encrypted" in msg):
                            raise ArtifactParseError("The private key is encrypted and requires a password.") from exc
                        if password_b is not None:
                            try:
                                key = serialization.load_pem_private_key(block, password=None)
                                encrypted_input = False
                            except Exception:
                                raise ArtifactParseError(
                                    "Unable to decrypt or parse the private key. The password may be incorrect."
                                ) from exc
                        else:
                            raise ArtifactParseError(f"Unable to parse the private key: {exc}") from exc
                    except ValueError as exc:
                        raise ArtifactParseError("Invalid private key or incorrect password.") from exc
                    except UnsupportedAlgorithm as exc:
                        raise ArtifactParseError(f"Unsupported private-key algorithm: {exc}") from exc
                    results.append(_private_key_parsed(key, "pem", encrypted_input))
                else:
                    errors.append(f"Unsupported PEM block: {header}")
            except ArtifactParseError:
                raise
            except Exception as exc:
                errors.append(f"{header}: {exc}")
        if errors:
            raise ArtifactParseError("; ".join(errors))
        if results:
            return results
        raise ArtifactParseError("No supported cryptographic object was found in the PEM input.")

    try:
        return [_certificate_parsed(x509.load_der_x509_certificate(data), "der")]
    except Exception:
        pass
    try:
        return [_csr_parsed(x509.load_der_x509_csr(data), "der")]
    except Exception:
        pass
    try:
        certs = pkcs7.load_der_pkcs7_certificates(data)
        if certs:
            return [_certificate_parsed(cert, "pkcs7") for cert in certs]
    except Exception:
        pass

    der_key_password_error = None
    try:
        key = serialization.load_der_private_key(data, password=password_b)
    except TypeError as exc:
        msg = str(exc).lower()
        if password_b is None and ("password was not given" in msg or "private key is encrypted" in msg):
            der_key_password_error = "The private key is encrypted and requires a password."
        elif password_b is not None:
            try:
                key = serialization.load_der_private_key(data, password=None)
            except Exception:
                key = None
            else:
                return [_private_key_parsed(key, "der", False)]
    except (ValueError, UnsupportedAlgorithm):
        pass
    else:
        return [_private_key_parsed(key, "der", password_b is not None)]

    p12_error = None
    try:
        key, cert, cas = pkcs12.load_key_and_certificates(data, password_b)
    except Exception as exc:
        p12_error = exc
    else:
        results = []
        if key is not None and cert is not None:
            if public_key_fingerprint(key.public_key()) != public_key_fingerprint(cert.public_key()):
                raise ArtifactParseError("The PKCS#12/PFX private key does not match the leaf certificate.")
        if key is not None:
            results.append(_private_key_parsed(key, "pkcs12", password_b is not None))
        if cert is not None:
            results.append(_certificate_parsed(cert, "pkcs12"))
        results.extend(_certificate_parsed(ca, "pkcs12") for ca in (cas or []))
        if results:
            return results
        raise ArtifactParseError("The PKCS#12/PFX container contains no supported private key or certificate.")

    if der_key_password_error:
        raise ArtifactParseError(der_key_password_error)
    if lower_name.endswith((".pfx", ".p12")):
        raise ArtifactParseError(
            "The file could not be decoded as PKCS#12/PFX. It may be invalid, corrupted, or protected by a different password."
        ) from p12_error
    if password_b is not None:
        raise ArtifactParseError(
            "Unsupported or invalid cryptographic file, or the supplied password is incorrect. Supported content includes "
            "X.509 certificates, CSRs, private keys, PKCS#7 certificate containers, and PKCS#12/PFX containers."
        )
    raise ArtifactParseError(
        "Unsupported or invalid cryptographic file. Supported content includes X.509 certificates, CSRs, private keys, "
        "PKCS#7 certificate containers, and PKCS#12/PFX containers."
    )
