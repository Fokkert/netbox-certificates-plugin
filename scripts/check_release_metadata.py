from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


errors = []

pyproject = read("pyproject.toml")
plugin_yaml = read("netbox-plugin.yaml")
config = read("netbox_certificates/__init__.py")

if 'version = "1.0.1"' not in pyproject:
    errors.append("pyproject.toml does not declare version 1.0.1")
if "version: 1.0.1" not in plugin_yaml:
    errors.append("netbox-plugin.yaml does not declare version 1.0.1")
if 'version = "1.0.1"' not in config:
    errors.append("PluginConfig does not declare version 1.0.1")
if 'min_version = "4.5.9"' not in config or 'max_version = "4.5.10"' not in config:
    errors.append("NetBox compatibility gate must remain 4.5.9 through 4.5.10")

navigation = read("netbox_certificates/navigation.py")
for required in (
    "Expiration Dashboard",
    "Certificate Authorities",
    "Cryptographic Vault",
    "Health and Validity",
    "Groups",
    "Services",
    "Bundles",
    "Certificates",
    "Private Keys",
    "CSRs",
    "Import Objects",
    "Generate CSR",
    "Alerts Configuration",
):
    if required not in navigation:
        errors.append(f"Navigation missing: {required}")

urls = read("netbox_certificates/urls.py")
for forbidden in (
    'path("inventory/"',
    'path("expiration-alerts/"',
    'name="link_add"',
    'name="link_remove"',
    "LegacyRedirect",
):
    if forbidden in urls:
        errors.append(f"Retired UI contract remains: {forbidden}")

api_urls = read("netbox_certificates/api/urls.py")
for forbidden in (
    'router.register("artifact-links"',
    'router.register("expiration-',
    'router.register("expiry-',
):
    if forbidden in api_urls:
        errors.append(f"Retired API registration remains: {forbidden}")
if "register_v1_routes(router)" not in api_urls:
    errors.append("1.0 API router was not integrated")

models = read("netbox_certificates/models.py")
if "from .models_v1 import" not in models:
    errors.append("1.0 models were not integrated into models.py")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print("Release metadata and 1.0 integration checks passed.")
