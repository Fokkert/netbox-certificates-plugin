from __future__ import annotations

import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
INIT = ROOT / "netbox_certificates" / "__init__.py"


def fail(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


with PYPROJECT.open("rb") as handle:
    metadata = tomllib.load(handle)

project_version = metadata["project"]["version"]
init_text = INIT.read_text(encoding="utf-8")
match = re.search(r'^\s*version\s*=\s*["\']([^"\']+)["\']', init_text, re.MULTILINE)
if not match:
    fail("Could not find PluginConfig.version in netbox_certificates/__init__.py")

plugin_version = match.group(1)
if plugin_version != project_version:
    fail(f"Version mismatch: pyproject={project_version}, plugin={plugin_version}")

placeholder_files: list[str] = []
for path in ROOT.rglob("*"):
    if not path.is_file() or ".git" in path.parts:
        continue
    if any(part in {"__pycache__", "dist", "build"} for part in path.parts):
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    placeholder = "YOUR" + "_GITHUB_OWNER"
    if placeholder in text:
        placeholder_files.append(str(path.relative_to(ROOT)))

if placeholder_files:
    fail("Unresolved GitHub owner placeholder(s): " + ", ".join(placeholder_files))

print(f"OK: release metadata is internally consistent for version {project_version}")
