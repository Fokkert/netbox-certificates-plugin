#!/usr/bin/env python3
"""Integrate the complete 1.0 overlay into an existing clean 0.5.0 source tree.

The update package deliberately does not replace legacy cryptographic model/API
implementation files wholesale: 1.0 preserves their established behavior and
adds the new model layer after those classes are defined.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path
import re
import sys


V1_MODEL_NAMES = (
    "AlertChannel",
    "AlertEvent",
    "AlertRule",
    "CertificatePolicy",
    "HealthFinding",
    "ObjectLink",
    "Service",
)

LEGACY_API_ROUTE_MARKERS = (
    "expiration-alert",
    "expiry-alert",
    "artifact-link",
)

CHANGELOG_ENTRY = """## 1.0.0

- Replace the pre-1.0 navigation with Overview, Inventory, and Operations sections.
- Replace Inventory with Cryptographic Vault.
- Restore Certificate Authorities as a view/API of actual CA Certificate objects.
- Add first-class Services with many-to-many cryptographic relationships and generic NetBox ObjectLinks.
- Add Certificate Policies and structured Health and Validity findings.
- Replace expiration-only alerting with configurable rules/channels/events for all Health findings.
- Fix the 0.5.0 material-export filter failure and add SHA-256 export manifests.
- Add relationship-aware filtering, global search, GraphQL coverage, NetBox-native metadata, and 1.0 permission actions.
- Add expandable Group tree while retaining native list/bulk/export behavior.
- Replace legacy ArtifactLink, CA identity, and expiration-alert public interfaces with the 1.0 object model.

"""


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def write(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")


def integrate_models(repo: Path) -> None:
    path = repo / "netbox_certificates" / "models.py"
    text = read(path)
    if "from .models_v1 import" in text:
        return
    block = "\n\n# Public 1.0 management models. Imported after the established cryptographic\n" \
            "# model classes to preserve their implementation and avoid circular initialization.\n" \
            "from .models_v1 import (\n" + "".join(f"    {name},\n" for name in V1_MODEL_NAMES) + ")\n"
    write(path, text.rstrip() + block)


def route_literal(call: ast.AST) -> str | None:
    if not isinstance(call, ast.Call) or not call.args:
        return None
    func = call.func
    name = func.id if isinstance(func, ast.Name) else getattr(func, "attr", None)
    if name not in {"path", "re_path"}:
        return None
    first = call.args[0]
    return first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None


def scrub_url_value(node: ast.AST) -> ast.AST:
    if isinstance(node, (ast.List, ast.Tuple)):
        kept = []
        for item in node.elts:
            route = route_literal(item)
            if route and any(marker in route.lower() for marker in LEGACY_API_ROUTE_MARKERS):
                continue
            kept.append(scrub_url_value(item))
        node.elts = kept
        return node
    if isinstance(node, ast.BinOp):
        node.left = scrub_url_value(node.left)
        node.right = scrub_url_value(node.right)
    return node


def integrate_api_urls(repo: Path) -> None:
    path = repo / "netbox_certificates" / "api" / "urls.py"
    source = read(path)
    tree = ast.parse(source)

    # Remove every pre-1.0 router registration. The 1.0 router owns the complete
    # public model endpoint set so old aliases cannot survive accidentally.
    new_body = []
    for node in tree.body:
        if (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and isinstance(node.value.func.value, ast.Name)
            and node.value.func.value.id == "router"
            and node.value.func.attr == "register"
        ):
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            target_names = []
            if isinstance(node, ast.Assign):
                target_names = [t.id for t in node.targets if isinstance(t, ast.Name)]
                if "urlpatterns" in target_names:
                    node.value = scrub_url_value(node.value)
            elif isinstance(node.target, ast.Name) and node.target.id == "urlpatterns":
                node.value = scrub_url_value(node.value)
        new_body.append(node)
    tree.body = new_body

    has_import = any(
        isinstance(node, ast.ImportFrom)
        and node.module == "v1_urls"
        and any(alias.name == "register_v1_routes" for alias in node.names)
        for node in tree.body
    )
    if not has_import:
        # Relative import: from .v1_urls import register_v1_routes
        import_node = ast.ImportFrom(
            module="v1_urls",
            names=[ast.alias(name="register_v1_routes")],
            level=1,
        )
        # Place after existing imports.
        insert_at = 0
        for i, node in enumerate(tree.body):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                insert_at = i + 1
        tree.body.insert(insert_at, import_node)

    has_call = any(
        isinstance(node, ast.Expr)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id == "register_v1_routes"
        for node in tree.body
    )
    if not has_call:
        insert_at = None
        for i, node in enumerate(tree.body):
            if isinstance(node, ast.Assign):
                if any(isinstance(t, ast.Name) and t.id == "router" for t in node.targets):
                    insert_at = i + 1
                    break
        if insert_at is None:
            raise RuntimeError("Could not locate API router assignment in netbox_certificates/api/urls.py")
        tree.body.insert(
            insert_at,
            ast.Expr(
                value=ast.Call(
                    func=ast.Name(id="register_v1_routes", ctx=ast.Load()),
                    args=[ast.Name(id="router", ctx=ast.Load())],
                    keywords=[],
                )
            ),
        )

    ast.fix_missing_locations(tree)
    write(path, ast.unparse(tree) + "\n")


def patch_source_references(repo: Path) -> None:
    extensions = {".py", ".html", ".md", ".txt"}
    replacements = (
        ("plugins:netbox_certificates:inventory", "plugins:netbox_certificates:vault"),
        ("netbox_certificates:inventory", "netbox_certificates:vault"),
        ("plugins:netbox_certificates:expiration_alerts", "plugins:netbox_certificates:alertrule_list"),
        ("netbox_certificates:expiration_alerts", "netbox_certificates:alertrule_list"),
        ("netbox-certificates-plugin/0.5.0", "netbox-certificates-plugin/1.0.0"),
    )
    link_add = re.compile(
        r"{%\s*url\s+['\"]plugins:netbox_certificates:link_add['\"][^%]*%}"
    )
    link_remove = re.compile(
        r"{%\s*url\s+['\"]plugins:netbox_certificates:link_remove['\"][^%]*%}"
    )

    for path in repo.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in extensions:
            continue
        if any(part in {".git", "__pycache__", "dist", "build"} for part in path.parts):
            continue
        # Changelog intentionally retains historical 0.5 text.
        text = read(path)
        updated = text
        for old, new in replacements:
            updated = updated.replace(old, new)
        if path.suffix.lower() == ".html":
            updated = link_add.sub(
                "{% url 'plugins:netbox_certificates:objectlink_add' %}",
                updated,
            )
            updated = link_remove.sub(
                "{% url 'plugins:netbox_certificates:objectlink_list' %}",
                updated,
            )
        if updated != text:
            write(path, updated)


def remove_retired_files(repo: Path) -> None:
    retired = (
        "netbox_certificates/templates/netbox_certificates/inventory.html",
        "netbox_certificates/templates/netbox_certificates/expiration_alerts.html",
        "netbox_certificates/templates/netbox_certificates/certificate_authority.html",
    )
    for relative in retired:
        path = repo / relative
        if path.exists():
            path.unlink()


def update_changelog(repo: Path) -> None:
    path = repo / "CHANGELOG.md"
    if path.exists():
        text = read(path)
        if re.search(r"(?m)^## 1\.0\.0\s*$", text):
            return
        if text.startswith("# Changelog"):
            first_line, sep, rest = text.partition("\n")
            write(path, first_line + "\n\n" + CHANGELOG_ENTRY + rest.lstrip("\n"))
        else:
            write(path, "# Changelog\n\n" + CHANGELOG_ENTRY + text)
    else:
        write(path, "# Changelog\n\n" + CHANGELOG_ENTRY)


def update_remaining_tests(repo: Path) -> None:
    # Payload replaces the release/bulk contracts. Other historical tests should
    # continue proving unchanged cryptographic behavior; only version literals
    # which explicitly refer to the current package release are advanced.
    test_dir = repo / "tests"
    if not test_dir.exists():
        return
    for path in test_dir.rglob("*.py"):
        text = read(path)
        if path.name in {"test_release_contract.py", "test_bulk_operations_contract.py", "test_v1_contract.py"}:
            continue
        updated = text.replace(
            'netbox-certificates-plugin/0.5.0',
            'netbox-certificates-plugin/1.0.0',
        )
        write(path, updated)


def validate_no_legacy_public_routes(repo: Path) -> None:
    urls = read(repo / "netbox_certificates" / "urls.py")
    api_urls = read(repo / "netbox_certificates" / "api" / "urls.py")

    forbidden_ui = (
        'path("inventory/"',
        'path("expiration-alerts/"',
        'name="link_add"',
        'name="link_remove"',
        "LegacyRedirect",
    )
    for marker in forbidden_ui:
        if marker in urls:
            raise RuntimeError(f"Retired UI route remains after integration: {marker}")

    if "register_v1_routes(router)" not in api_urls:
        raise RuntimeError("1.0 API route registration was not integrated.")
    if "router.register(" in api_urls:
        raise RuntimeError(
            "A direct pre-1.0 router.register() remains in api/urls.py; "
            "all public model registration must be owned by register_v1_routes()."
        )

    models = read(repo / "netbox_certificates" / "models.py")
    if "from .models_v1 import" not in models:
        raise RuntimeError("1.0 models were not imported by models.py.")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("repo", type=Path)
    args = parser.parse_args()
    repo = args.repo.resolve()

    if not (repo / "netbox_certificates" / "models.py").exists():
        raise SystemExit(f"Not a netbox-certificates-plugin source tree: {repo}")

    integrate_models(repo)
    integrate_api_urls(repo)
    patch_source_references(repo)
    remove_retired_files(repo)
    update_changelog(repo)
    update_remaining_tests(repo)
    validate_no_legacy_public_routes(repo)

    print("1.0 integration completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
