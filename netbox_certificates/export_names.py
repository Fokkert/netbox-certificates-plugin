"""Shared, path-safe names for UI and API Bundle exports."""
import re
import unicodedata


def certificate_export_name(bundle):
    certificate = getattr(bundle, "certificate", None)
    name = getattr(certificate, "name", "") or getattr(bundle, "name", "") or f"bundle-{bundle.pk}"
    name = unicodedata.normalize("NFC", str(name))
    name = "".join("_" if unicodedata.category(char).startswith("C") else char for char in name)
    name = re.sub(r'[<>:"/\\|?*]', "_", name).strip(" .")[:120].rstrip(" .")
    name = name.encode("utf-8")[:160].decode("utf-8", errors="ignore").rstrip(" .")
    if not name:
        name = f"bundle-{bundle.pk}"
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}
    if name.split(".")[0].upper() in reserved:
        name = "_" + name
    return name


def bundle_export_name(bundle, extension=""):
    return f"{certificate_export_name(bundle)}'s Bundle{extension}"


def pfx_export_name(bundle):
    return f"{certificate_export_name(bundle)}.pfx"


def unique_bundle_directory(bundle, used):
    """Keep readable names, disambiguating only collisions in bulk archives."""
    base = bundle_export_name(bundle)
    candidate = base
    counter = 2
    while candidate.casefold() in used:
        candidate = f"{base} ({counter})"
        counter += 1
    used.add(candidate.casefold())
    return candidate
