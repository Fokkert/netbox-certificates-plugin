from cryptography import x509


def load_certificate(obj):
    return x509.load_pem_x509_certificate(obj.material.encode("ascii"))


def ordered_chain(leaf, additional=None, max_depth=16):
    allowed = None if additional is None else {c.pk: c for c in additional}
    result, current, seen = [], leaf, {leaf.pk}
    for _ in range(max_depth):
        parent = current.parent_certificate
        if parent is None or parent.pk in seen:
            break
        if allowed is not None and parent.pk not in allowed:
            break
        result.append(parent)
        seen.add(parent.pk)
        current = parent
    return result


def validate_chain(leaf, max_depth=16):
    checks, current_obj, seen, subordinate_ca_count = [], leaf, set(), 0
    for _ in range(max_depth):
        if current_obj.pk in seen:
            checks.append({"object": current_obj, "ok": False, "message": "Certificate chain contains a cycle."})
            return {"valid": False, "complete": False, "checks": checks}
        seen.add(current_obj.pk)
        try:
            current = load_certificate(current_obj)
        except Exception as exc:
            checks.append({"object": current_obj, "ok": False, "message": f"Stored certificate cannot be parsed: {exc}"})
            return {"valid": False, "complete": False, "checks": checks}
        if current.subject == current.issuer:
            try:
                current.verify_directly_issued_by(current)
            except Exception:
                checks.append({"object": current_obj, "ok": False, "message": "Root/self-signed certificate signature is invalid."})
                return {"valid": False, "complete": True, "checks": checks}
            checks.append({"object": current_obj, "ok": True, "message": "Self-signed root verified."})
            return {"valid": True, "complete": True, "checks": checks}
        parent_obj = current_obj.parent_certificate
        if parent_obj is None:
            checks.append({"object": current_obj, "ok": False, "message": "Issuer certificate is not stored or not linked."})
            return {"valid": False, "complete": False, "checks": checks}
        try:
            parent = load_certificate(parent_obj)
            current.verify_directly_issued_by(parent)
        except Exception:
            checks.append({"object": current_obj, "ok": False, "message": "Issuer signature validation failed."})
            return {"valid": False, "complete": True, "checks": checks}
        try:
            bc = parent.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not bc.ca:
                raise ValueError("issuer is not a CA")
            ca_below_parent = subordinate_ca_count + (1 if current_obj.is_ca else 0)
            if bc.path_length is not None and ca_below_parent > bc.path_length:
                raise ValueError(f"pathLenConstraint={bc.path_length} is exceeded")
        except x509.ExtensionNotFound:
            checks.append({"object": parent_obj, "ok": False, "message": "Issuer lacks a CA BasicConstraints extension."})
            return {"valid": False, "complete": True, "checks": checks}
        except ValueError as exc:
            checks.append({"object": parent_obj, "ok": False, "message": str(exc)})
            return {"valid": False, "complete": True, "checks": checks}
        try:
            ku = parent.extensions.get_extension_for_class(x509.KeyUsage).value
            if not ku.key_cert_sign:
                checks.append({"object": parent_obj, "ok": False, "message": "Issuer KeyUsage does not permit certificate signing."})
                return {"valid": False, "complete": True, "checks": checks}
        except x509.ExtensionNotFound:
            pass
        checks.append({"object": current_obj, "ok": True, "message": "Issuer signature verified."})
        if current_obj.is_ca:
            subordinate_ca_count += 1
        current_obj = parent_obj
    checks.append({"object": current_obj, "ok": False, "message": "Maximum chain depth exceeded."})
    return {"valid": False, "complete": False, "checks": checks}
