import hashlib
import ipaddress
import json
from collections import defaultdict
from datetime import timedelta
from urllib.parse import urlparse

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from django.contrib.contenttypes.models import ContentType
from django.db import transaction
from django.db.models import Max, Q
from django.utils import timezone

from ..choices_v1 import FindingSeverityChoices, FindingStatusChoices
from ..models import Bundle, Certificate, CSR, PrivateKey
from ..models_v1 import AlertRule, CertificatePolicy, HealthFinding, Service


ACTIVE = FindingStatusChoices.ACTIVE


def _stable_fingerprint(code, obj, related=None, evidence=None):
    # A finding fingerprint identifies the logical problem, not its volatile
    # evidence. For example, CERT_EXPIRING must remain one finding while
    # days_remaining changes on every scan.
    payload = {
        "code": code,
        "object": f"{obj._meta.label_lower}:{obj.pk}",
        "related": f"{related._meta.label_lower}:{related.pk}" if related else None,
    }
    raw = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _finding(code, category, severity, obj, summary, *, related=None, details=None, evidence=None):
    now = timezone.now()
    fingerprint = _stable_fingerprint(code, obj, related=related, evidence=evidence)
    object_type = ContentType.objects.get_for_model(obj, for_concrete_model=False)
    related_type = (
        ContentType.objects.get_for_model(related, for_concrete_model=False)
        if related is not None
        else None
    )
    finding, created = HealthFinding.objects.update_or_create(
        fingerprint=fingerprint,
        defaults={
            "code": code,
            "category": category,
            "severity": severity,
            "object_type": object_type,
            "object_id": obj.pk,
            "related_type": related_type,
            "related_object_id": related.pk if related is not None else None,
            "summary": summary,
            "details": details or {},
            "evidence": evidence or {},
            "last_detected": now,
            "resolved_at": None,
        },
    )
    if created:
        finding.first_detected = now
    if finding.status == FindingStatusChoices.RESOLVED:
        finding.status = ACTIVE
    finding.save()
    return finding


def _value(obj, *names, default=None):
    for name in names:
        if hasattr(obj, name):
            value = getattr(obj, name)
            if value is not None:
                return value
    return default


def _certificate_sans(cert):
    value = _value(cert, "sans", "subject_alt_names", "san", default=[])
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return []
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return [str(item).strip() for item in parsed if str(item).strip()]
        except Exception:
            pass
        return [item.strip() for item in stripped.replace(";", ",").split(",") if item.strip()]
    if isinstance(value, (tuple, list, set)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _normalize_identity(value):
    value = str(value or "").strip()
    for prefix in ("DNS:", "dns:", "IP:", "ip:", "IP Address:", "URI:"):
        if value.startswith(prefix):
            value = value[len(prefix):].strip()
            break
    return value.rstrip(".").lower()


def _dns_match(pattern, hostname):
    pattern = _normalize_identity(pattern)
    hostname = _normalize_identity(hostname)
    if not pattern or not hostname:
        return False
    try:
        return ipaddress.ip_address(pattern) == ipaddress.ip_address(hostname)
    except ValueError:
        pass
    if pattern.startswith("*."):
        suffix = pattern[2:]
        host_parts = hostname.split(".")
        suffix_parts = suffix.split(".")
        return len(host_parts) == len(suffix_parts) + 1 and hostname.endswith("." + suffix)
    return pattern == hostname


def _service_hostnames(service):
    names = set()
    for value in (service.hostname, service.sni_name):
        if value:
            names.add(_normalize_identity(value))
    urls = [service.primary_url, *(service.additional_urls or [])]
    for raw in urls:
        if not raw:
            continue
        try:
            host = urlparse(str(raw)).hostname
        except Exception:
            host = None
        if host:
            names.add(_normalize_identity(host))
    return {name for name in names if name}


def _cert_covers_service(cert, service):
    names = _service_hostnames(service)
    if not names:
        return True, []
    sans = [_normalize_identity(item) for item in _certificate_sans(cert)]
    sans = [item for item in sans if item]
    if not sans:
        subject = str(_value(cert, "subject", default="") or "")
        for part in subject.split(","):
            key, sep, value = part.strip().partition("=")
            if sep and key.strip().upper() in {"CN", "COMMONNAME"}:
                sans.append(_normalize_identity(value))
                break
    missing = [host for host in sorted(names) if not any(_dns_match(pattern, host) for pattern in sans)]
    return not missing, missing


def _key_bits(obj):
    return _value(obj, "key_size", "key_bits", "size", default=None)


def _key_type(obj):
    return str(_value(obj, "key_type", "algorithm", default="") or "").upper()


def _key_curve(obj):
    return str(_value(obj, "curve", "key_curve", "ec_curve", default="") or "").strip().lower()


def _weak_curve(curve):
    curve = str(curve or "").lower()
    return curve in {"secp192r1", "prime192v1", "secp224r1"}


def _public_key_fingerprint(obj):
    return str(_value(obj, "public_key_fingerprint", default="") or "").lower()


def _material_fingerprint(obj):
    return str(_value(obj, "fingerprint_sha256", "material_fingerprint", "fingerprint", default="") or "").lower()


def _validity(cert):
    not_before = _value(cert, "not_before", "valid_from")
    not_after = _value(cert, "not_after", "valid_until", "expires")
    return not_before, not_after


def _evaluate_policy(policy, certificate):
    violations = []
    if not policy or not policy.enabled:
        return violations
    key_type = _key_type(certificate)
    bits = _key_bits(certificate)
    sig = str(_value(certificate, "signature_algorithm", default="") or "").lower()
    curve = str(_value(certificate, "curve", "key_curve", default="") or "").lower()
    is_ca = bool(_value(certificate, "is_ca", default=False))
    sans = _certificate_sans(certificate)
    issuer = str(_value(certificate, "issuer", default="") or "")

    if "RSA" in key_type and bits and bits < policy.minimum_rsa_bits:
        violations.append(f"RSA key size {bits} is below policy minimum {policy.minimum_rsa_bits}.")
    if policy.allowed_key_types and key_type and key_type.lower() not in {str(x).lower() for x in policy.allowed_key_types}:
        violations.append(f"Key type {key_type} is not allowed.")
    if policy.allowed_signature_algorithms and sig and sig not in {str(x).lower() for x in policy.allowed_signature_algorithms}:
        violations.append(f"Signature algorithm {sig} is not allowed.")
    if policy.allowed_curves and curve and curve not in {str(x).lower() for x in policy.allowed_curves}:
        violations.append(f"Curve {curve} is not allowed.")
    if policy.require_san and not sans:
        violations.append("Subject Alternative Name is required.")
    if not policy.allow_wildcards and any(_normalize_identity(x).startswith("*.") for x in sans):
        violations.append("Wildcard SANs are not allowed.")
    if is_ca and not policy.allow_ca:
        violations.append("CA certificates are not allowed by this policy.")
    if policy.allowed_issuers and issuer and issuer not in set(policy.allowed_issuers):
        violations.append("Issuer is not in the policy allow-list.")
    public_key_fingerprint = _public_key_fingerprint(certificate)
    if policy.forbid_key_reuse and public_key_fingerprint:
        certificate_matches = Certificate.objects.filter(public_key_fingerprint=public_key_fingerprint)
        if isinstance(certificate, Certificate):
            certificate_matches = certificate_matches.exclude(pk=certificate.pk)
        certificate_reuse = certificate_matches.exists()
        service_reuse = Service.objects.filter(
            Q(certificates__public_key_fingerprint=public_key_fingerprint)
            | Q(private_keys__public_key_fingerprint=public_key_fingerprint)
            | Q(bundles__certificate__public_key_fingerprint=public_key_fingerprint)
            | Q(bundles__private_key__public_key_fingerprint=public_key_fingerprint)
        ).distinct().count() > 1
        if certificate_reuse or service_reuse:
            violations.append("Public/private key reuse is forbidden by this policy.")
    not_before, not_after = _validity(certificate)
    if policy.max_validity_days and not_before and not_after:
        try:
            days = (not_after - not_before).days
            if days > policy.max_validity_days:
                violations.append(f"Validity {days} days exceeds policy maximum {policy.max_validity_days}.")
        except TypeError:
            pass
    return violations


def _verify_parent_signature(cert):
    parent = _value(cert, "parent_certificate", "parent")
    if not parent or not getattr(cert, "material", None) or not getattr(parent, "material", None):
        return None
    try:
        child_x509 = x509.load_pem_x509_certificate(cert.material.encode())
        parent_x509 = x509.load_pem_x509_certificate(parent.material.encode())
        # cryptography performs algorithm-specific signature verification here
        # (RSA, ECDSA, EdDSA, etc.) and also verifies issuer/subject linkage.
        child_x509.verify_directly_issued_by(parent_x509)
        return True
    except Exception:
        return False


def _certificate_findings(cert, now, expiry_horizon_days=90):
    not_before, not_after = _validity(cert)
    if not_before and now < not_before:
        _finding("CERT_NOT_YET_VALID", "validity", FindingSeverityChoices.HIGH, cert, "Certificate is not yet valid.")
    if not_after:
        if now >= not_after:
            _finding("CERT_EXPIRED", "validity", FindingSeverityChoices.CRITICAL, cert, "Certificate has expired.")
        else:
            remaining = not_after - now
            if remaining <= timedelta(days=7):
                sev = FindingSeverityChoices.HIGH
            elif remaining <= timedelta(days=30):
                sev = FindingSeverityChoices.MEDIUM
            elif remaining <= timedelta(days=90):
                sev = FindingSeverityChoices.WARNING
            elif remaining <= timedelta(days=expiry_horizon_days):
                sev = FindingSeverityChoices.INFO
            else:
                sev = None
            if sev:
                _finding(
                    "CERT_EXPIRING",
                    "validity",
                    sev,
                    cert,
                    f"Certificate expires in {max(0, remaining.days)} days.",
                    evidence={"days_remaining": remaining.days},
                )

    key_type = _key_type(cert)
    bits = _key_bits(cert)
    if "RSA" in key_type and bits and bits < 2048:
        _finding(
            "WEAK_RSA_CERTIFICATE",
            "security",
            FindingSeverityChoices.HIGH,
            cert,
            f"Certificate uses an RSA key of only {bits} bits.",
            evidence={"bits": bits},
        )
    curve = _key_curve(cert)
    if _weak_curve(curve) or (("EC" in key_type or "ECDSA" in key_type) and bits and bits < 256):
        _finding(
            "WEAK_EC_CERTIFICATE",
            "security",
            FindingSeverityChoices.HIGH,
            cert,
            "Certificate uses an elliptic-curve key below the plugin's modern TLS baseline.",
            evidence={"curve": curve, "bits": bits},
        )
    sig = str(_value(cert, "signature_algorithm", default="") or "").lower()
    if "sha1" in sig or "md5" in sig:
        _finding(
            "WEAK_SIGNATURE_ALGORITHM",
            "security",
            FindingSeverityChoices.CRITICAL,
            cert,
            f"Certificate uses weak signature algorithm {sig}.",
        )

    parent = _value(cert, "parent_certificate", "parent")
    is_ca = bool(_value(cert, "is_ca", default=False))
    subject = str(_value(cert, "subject", default="") or "")
    issuer = str(_value(cert, "issuer", default="") or "")
    self_signed = bool(subject and issuer and subject == issuer)
    if not self_signed and not parent and issuer:
        issuer_candidates = list(Certificate.objects.filter(subject=issuer).exclude(pk=cert.pk)[:3])
        if len(issuer_candidates) > 1:
            _finding(
                "AMBIGUOUS_ISSUER",
                "chain",
                FindingSeverityChoices.HIGH,
                cert,
                "More than one imported certificate could be the issuer.",
                evidence={"candidate_ids": [candidate.pk for candidate in issuer_candidates]},
            )
        else:
            _finding(
                "MISSING_ISSUER_RELATIONSHIP",
                "chain",
                FindingSeverityChoices.HIGH,
                cert,
                "Certificate issuer relationship could not be resolved.",
            )
    if parent:
        p_not_before, p_not_after = _validity(parent)
        if not bool(_value(parent, "is_ca", default=False)):
            _finding(
                "ISSUER_NOT_CA",
                "chain",
                FindingSeverityChoices.CRITICAL,
                cert,
                "Linked issuer certificate is not marked as a CA certificate.",
                related=parent,
            )
        if p_not_before and now < p_not_before:
            _finding(
                "ISSUER_NOT_YET_VALID",
                "chain",
                FindingSeverityChoices.HIGH,
                cert,
                "Certificate chain contains an issuer which is not yet valid.",
                related=parent,
            )
        if p_not_after and now >= p_not_after:
            _finding(
                "EXPIRED_ISSUER",
                "chain",
                FindingSeverityChoices.CRITICAL,
                cert,
                "Certificate chain contains an expired issuer certificate.",
                related=parent,
            )
        verified = _verify_parent_signature(cert)
        if verified is False:
            _finding(
                "INVALID_PARENT_SIGNATURE",
                "chain",
                FindingSeverityChoices.CRITICAL,
                cert,
                "Certificate signature does not validate against its linked parent.",
                related=parent,
            )

    # Detect relationship cycles and unresolvable roots without trusting a fixed depth.
    seen_ids = set()
    current = cert
    depth = 0
    while current is not None and depth < 128:
        if current.pk in seen_ids:
            _finding(
                "CERTIFICATE_CHAIN_LOOP",
                "chain",
                FindingSeverityChoices.CRITICAL,
                cert,
                "Certificate parent relationships contain a loop.",
                evidence={"loop_at_certificate_id": current.pk},
            )
            break
        seen_ids.add(current.pk)
        next_parent = _value(current, "parent_certificate", "parent")
        if next_parent is None:
            break
        current = next_parent
        depth += 1
    if depth >= 128:
        _finding(
            "CERTIFICATE_CHAIN_DEPTH_LIMIT",
            "chain",
            FindingSeverityChoices.CRITICAL,
            cert,
            "Certificate chain exceeded the safety depth limit.",
        )

    if self_signed and is_ca and getattr(cert, "material", None):
        try:
            parsed_root = x509.load_pem_x509_certificate(cert.material.encode())
            parsed_root.verify_directly_issued_by(parsed_root)
        except Exception:
            _finding(
                "INVALID_ROOT_SELF_SIGNATURE",
                "chain",
                FindingSeverityChoices.CRITICAL,
                cert,
                "Self-signed root certificate does not validate against its own public key.",
            )

    if not self_signed and not bool(_value(cert, "authority", default=None)):
        _finding(
            "UNRESOLVED_ROOT_CA",
            "chain",
            FindingSeverityChoices.WARNING,
            cert,
            "Certificate does not resolve to an imported root CA identity.",
        )


def _duplicate_findings(model, attr, code, category, severity, label):
    buckets = defaultdict(list)
    for obj in model.objects.all():
        value = str(_value(obj, attr, default="") or "").strip().lower()
        if value:
            buckets[value].append(obj)
    for value, objects in buckets.items():
        if len(objects) < 2:
            continue
        for obj in objects:
            peers = [peer.pk for peer in objects if peer.pk != obj.pk]
            _finding(
                code,
                category,
                severity,
                obj,
                f"{label} is duplicated across {len(objects)} objects.",
                evidence={"duplicate_object_ids": peers, "fingerprint": value},
            )


def _bundle_findings(bundle):
    cert = _value(bundle, "certificate")
    key = _value(bundle, "private_key")
    csr = _value(bundle, "csr")
    primaries = [item for item in (cert, key, csr) if item is not None]
    if len(primaries) < 2:
        _finding(
            "BUNDLE_INCOMPLETE",
            "relationship",
            FindingSeverityChoices.MEDIUM,
            bundle,
            "Bundle has fewer than two primary cryptographic artifacts.",
        )
        return
    fingerprints = {_public_key_fingerprint(item) for item in primaries if _public_key_fingerprint(item)}
    if len(fingerprints) > 1:
        _finding(
            "BUNDLE_PUBLIC_KEY_MISMATCH",
            "relationship",
            FindingSeverityChoices.CRITICAL,
            bundle,
            "Bundle primary artifacts do not share the same public key.",
            evidence={"public_key_fingerprints": sorted(fingerprints)},
        )


def _private_key_findings(key, now):
    key_type = _key_type(key)
    bits = _key_bits(key)
    curve = _key_curve(key)
    if "RSA" in key_type and bits and bits < 2048:
        _finding(
            "WEAK_RSA_PRIVATE_KEY",
            "security",
            FindingSeverityChoices.CRITICAL,
            key,
            f"Private key uses only {bits} RSA bits.",
            evidence={"bits": bits},
        )
    if _weak_curve(curve) or (("EC" in key_type or "ECDSA" in key_type) and bits and bits < 256):
        _finding(
            "WEAK_EC_PRIVATE_KEY",
            "security",
            FindingSeverityChoices.HIGH,
            key,
            "Private key uses an elliptic curve below the plugin's modern TLS baseline.",
            evidence={"curve": curve, "bits": bits},
        )
    if "DSA" in key_type:
        _finding(
            "DEPRECATED_DSA_PRIVATE_KEY",
            "security",
            FindingSeverityChoices.HIGH,
            key,
            "Private key uses DSA, which is unsuitable for modern TLS deployments.",
        )

    public_fingerprint = _public_key_fingerprint(key)
    matching_certificates = list(
        Certificate.objects.filter(public_key_fingerprint=public_fingerprint)
        if public_fingerprint
        else Certificate.objects.none()
    )
    active_certificates = []
    for certificate in matching_certificates:
        not_before, not_after = _validity(certificate)
        if (not_before is None or not_before <= now) and (not_after is None or now < not_after):
            active_certificates.append(certificate)

    if len(active_certificates) > 1:
        identity_sets = set()
        for certificate in active_certificates:
            identities = tuple(sorted(_normalize_identity(value) for value in _certificate_sans(certificate) if value))
            if not identities:
                identities = (str(_value(certificate, "subject", default="") or "").strip().lower(),)
            identity_sets.add(identities)
        distinct_identities = len(identity_sets) > 1
        _finding(
            "PRIVATE_KEY_REUSED_ACROSS_ACTIVE_CERTIFICATES",
            "security",
            FindingSeverityChoices.HIGH if distinct_identities else FindingSeverityChoices.WARNING,
            key,
            (
                "Private key is simultaneously used by certificates with different identities."
                if distinct_identities
                else "Private key is simultaneously used by multiple active certificates."
            ),
            evidence={
                "certificate_ids": [certificate.pk for certificate in active_certificates],
                "distinct_certificate_identities": distinct_identities,
            },
        )

    if not key.services.exists() and not matching_certificates:
        _finding(
            "ORPHAN_PRIVATE_KEY",
            "relationship",
            FindingSeverityChoices.WARNING,
            key,
            "Private key is not linked to a Service and no matching Certificate was found.",
        )


def _csr_findings(csr):
    key_type = _key_type(csr)
    bits = _key_bits(csr)
    curve = _key_curve(csr)
    if "RSA" in key_type and bits and bits < 2048:
        _finding(
            "WEAK_RSA_CSR",
            "security",
            FindingSeverityChoices.HIGH,
            csr,
            f"CSR requests an RSA key of only {bits} bits.",
            evidence={"bits": bits},
        )
    if _weak_curve(curve) or (("EC" in key_type or "ECDSA" in key_type) and bits and bits < 256):
        _finding(
            "WEAK_EC_CSR",
            "security",
            FindingSeverityChoices.HIGH,
            csr,
            "CSR uses an elliptic curve below the plugin's modern TLS baseline.",
            evidence={"curve": curve, "bits": bits},
        )
    signature = str(_value(csr, "signature_algorithm", default="") or "").lower()
    if "sha1" in signature or "md5" in signature:
        _finding(
            "WEAK_CSR_SIGNATURE_ALGORITHM",
            "security",
            FindingSeverityChoices.HIGH,
            csr,
            f"CSR uses weak signature algorithm {signature}.",
        )

    fingerprint = _public_key_fingerprint(csr)
    if not csr.services.exists() and fingerprint:
        matching_key = PrivateKey.objects.filter(public_key_fingerprint=fingerprint).exists()
        matching_cert = Certificate.objects.filter(public_key_fingerprint=fingerprint).exists()
        if not matching_key and not matching_cert:
            _finding(
                "ORPHAN_CSR",
                "relationship",
                FindingSeverityChoices.INFO,
                csr,
                "CSR is not linked to a Service and has no matching stored key or certificate.",
            )


def _certificate_service_reuse_findings(cert):
    if bool(_value(cert, "is_ca", default=False)):
        return

    services = list(
        Service.objects.filter(
            Q(certificates=cert) | Q(bundles__certificate=cert),
            enabled=True,
        ).distinct()
    )
    if len(services) <= 1:
        return

    sans = {_normalize_identity(item) for item in _certificate_sans(cert)}
    wildcard = any(item.startswith("*.") for item in sans)
    if wildcard:
        return

    endpoint_names = sorted({
        endpoint
        for service in services
        for endpoint in _service_hostnames(service)
    })
    evidence = {
        "service_ids": [service.pk for service in services],
        "endpoint_names": endpoint_names,
        "certificate_sans": sorted(sans),
    }
    if len(endpoint_names) > 1:
        severity = FindingSeverityChoices.HIGH
        code = "NON_WILDCARD_CERT_REUSED_ACROSS_SERVICES"
        summary = (
            "A non-wildcard certificate is linked to multiple Services with "
            "different endpoint identities."
        )
    else:
        severity = FindingSeverityChoices.WARNING
        code = "SINGLE_HOST_CERT_SHARED_ACROSS_SERVICES"
        summary = (
            "A non-wildcard certificate is shared by multiple Services. "
            "Verify that the Services represent the same TLS endpoint."
        )
    _finding(code, "service", severity, cert, summary, evidence=evidence)


def _service_findings(service):
    if not service.enabled:
        return
    certs = list(service.certificates.all())
    bundles = list(service.bundles.select_related("certificate", "private_key", "csr"))
    effective_certs = certs + [bundle.certificate for bundle in bundles if bundle.certificate_id]
    seen = set()
    effective_certs = [c for c in effective_certs if not (c.pk in seen or seen.add(c.pk))]

    if not effective_certs and service.protocol.lower() in {"https", "tls", "ssl", "ldaps", "smtps", "imaps", "pop3s"}:
        _finding(
            "SERVICE_WITHOUT_CERTIFICATE",
            "service",
            FindingSeverityChoices.HIGH,
            service,
            "TLS-capable Service has no linked Certificate or Certificate-bearing Bundle.",
        )

    for cert in effective_certs:
        valid, missing = _cert_covers_service(cert, service)
        if not valid:
            _finding(
                "SERVICE_NAME_NOT_COVERED",
                "service",
                FindingSeverityChoices.CRITICAL,
                service,
                "Linked certificate does not cover every Service hostname.",
                related=cert,
                evidence={"uncovered_names": missing},
            )

    linked_keys = list(service.private_keys.all()) + [b.private_key for b in bundles if b.private_key_id]

    cert_fingerprints = {_public_key_fingerprint(cert) for cert in effective_certs if _public_key_fingerprint(cert)}
    key_fingerprints = {_public_key_fingerprint(key) for key in linked_keys if key and _public_key_fingerprint(key)}
    if cert_fingerprints and key_fingerprints and cert_fingerprints.isdisjoint(key_fingerprints):
        _finding(
            "SERVICE_CERTIFICATE_KEY_MISMATCH",
            "relationship",
            FindingSeverityChoices.CRITICAL,
            service,
            "The Service has linked certificates and private keys, but none of their public-key identities match.",
            evidence={
                "certificate_public_keys": sorted(cert_fingerprints),
                "private_key_public_keys": sorted(key_fingerprints),
            },
        )

    linked_csrs = list(service.csrs.all()) + [b.csr for b in bundles if b.csr_id]
    csr_fingerprints = {_public_key_fingerprint(csr) for csr in linked_csrs if csr and _public_key_fingerprint(csr)}
    if cert_fingerprints and csr_fingerprints and cert_fingerprints.isdisjoint(csr_fingerprints):
        _finding(
            "SERVICE_CERTIFICATE_CSR_MISMATCH",
            "relationship",
            FindingSeverityChoices.HIGH,
            service,
            "The Service has linked certificates and CSRs, but none of their public-key identities match.",
            evidence={
                "certificate_public_keys": sorted(cert_fingerprints),
                "csr_public_keys": sorted(csr_fingerprints),
            },
        )
    if key_fingerprints and csr_fingerprints and key_fingerprints.isdisjoint(csr_fingerprints):
        _finding(
            "SERVICE_PRIVATE_KEY_CSR_MISMATCH",
            "relationship",
            FindingSeverityChoices.CRITICAL,
            service,
            "The Service has linked private keys and CSRs, but none of their public-key identities match.",
            evidence={
                "private_key_public_keys": sorted(key_fingerprints),
                "csr_public_keys": sorted(csr_fingerprints),
            },
        )

    fingerprints = defaultdict(list)
    for key in linked_keys:
        if key and _public_key_fingerprint(key):
            fingerprints[_public_key_fingerprint(key)].append(key)
    for fp, keys in fingerprints.items():
        service_ids = set(
            Service.objects.filter(
                Q(private_keys__public_key_fingerprint=fp)
                | Q(bundles__private_key__public_key_fingerprint=fp)
            ).values_list("pk", flat=True)
        )
        if len(service_ids) > 1:
            _finding(
                "PRIVATE_KEY_REUSED_ACROSS_SERVICES",
                "security",
                FindingSeverityChoices.HIGH,
                service,
                "A private key linked to this Service is reused by another Service.",
                evidence={"public_key_fingerprint": fp},
            )

    if service.policy:
        for cert in effective_certs:
            violations = _evaluate_policy(service.policy, cert)
            if violations:
                _finding(
                    "CERTIFICATE_POLICY_VIOLATION",
                    "policy",
                    FindingSeverityChoices.HIGH,
                    cert,
                    f"Certificate violates policy {service.policy.name}.",
                    related=service,
                    evidence={"violations": violations, "policy_id": service.policy_id},
                )


@transaction.atomic
def refresh_health_findings():
    started = timezone.now()
    now = timezone.now()

    configured_horizon = (
        AlertRule.objects.filter(enabled=True, expiration_days__isnull=False)
        .aggregate(value=Max("expiration_days"))
        .get("value")
        or 0
    )
    expiry_horizon_days = max(90, configured_horizon)

    for cert in Certificate.objects.all():
        _certificate_findings(cert, now, expiry_horizon_days=expiry_horizon_days)
        _certificate_service_reuse_findings(cert)
    for key in PrivateKey.objects.all():
        _private_key_findings(key, now)
    for csr in CSR.objects.all():
        _csr_findings(csr)
    for bundle in Bundle.objects.select_related("certificate", "private_key", "csr"):
        _bundle_findings(bundle)
    for service in Service.objects.prefetch_related(
        "certificates", "private_keys", "csrs", "bundles__certificate", "bundles__private_key", "bundles__csr"
    ):
        _service_findings(service)

    # Policies may be attached directly to certificates/CSRs/Bundles as well as inherited through Services.
    for policy in CertificatePolicy.objects.filter(enabled=True).prefetch_related(
        "certificates", "csrs", "bundles__certificate", "bundles__csr"
    ):
        for cert in policy.certificates.all():
            violations = _evaluate_policy(policy, cert)
            if violations:
                _finding(
                    "CERTIFICATE_POLICY_VIOLATION",
                    "policy",
                    FindingSeverityChoices.HIGH,
                    cert,
                    f"Certificate violates policy {policy.name}.",
                    related=policy,
                    evidence={"violations": violations, "policy_id": policy.pk},
                )
        for csr in policy.csrs.all():
            violations = _evaluate_policy(policy, csr)
            if violations:
                _finding(
                    "CSR_POLICY_VIOLATION",
                    "policy",
                    FindingSeverityChoices.HIGH,
                    csr,
                    f"CSR violates policy {policy.name}.",
                    related=policy,
                    evidence={"violations": violations, "policy_id": policy.pk},
                )
        for bundle in policy.bundles.all():
            for artifact in (bundle.certificate, bundle.csr):
                if artifact is None:
                    continue
                violations = _evaluate_policy(policy, artifact)
                if violations:
                    _finding(
                        "BUNDLE_POLICY_VIOLATION",
                        "policy",
                        FindingSeverityChoices.HIGH,
                        bundle,
                        f"Bundle violates policy {policy.name}.",
                        related=policy,
                        evidence={
                            "artifact_type": artifact._meta.label_lower,
                            "artifact_id": artifact.pk,
                            "violations": violations,
                            "policy_id": policy.pk,
                        },
                    )

    _duplicate_findings(
        Certificate,
        "fingerprint_sha256",
        "DUPLICATE_CERTIFICATE",
        "duplicate",
        FindingSeverityChoices.WARNING,
        "Certificate material",
    )
    _duplicate_findings(
        PrivateKey,
        "public_key_fingerprint",
        "DUPLICATE_PRIVATE_KEY",
        "duplicate",
        FindingSeverityChoices.HIGH,
        "Private-key public identity",
    )
    _duplicate_findings(
        CSR,
        "fingerprint_sha256",
        "DUPLICATE_CSR",
        "duplicate",
        FindingSeverityChoices.INFO,
        "CSR material",
    )
    _duplicate_findings(
        Bundle,
        "identity_fingerprint",
        "DUPLICATE_BUNDLE",
        "duplicate",
        FindingSeverityChoices.WARNING,
        "Bundle cryptographic identity",
    )

    # Resolve findings that were active before this run but were not observed again.
    stale = HealthFinding.objects.exclude(
        status=FindingStatusChoices.RESOLVED,
    ).filter(last_detected__lt=started)
    stale.update(status=FindingStatusChoices.RESOLVED, resolved_at=timezone.now())

    return {
        "active": HealthFinding.objects.filter(status=FindingStatusChoices.ACTIVE).count(),
        "total": HealthFinding.objects.count(),
    }
