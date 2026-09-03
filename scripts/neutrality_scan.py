from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]

# This is deliberately narrow: the repository URL/project maintainer identity is
# legitimate project metadata. The scan targets common accidental local/company
# artifacts, absolute user paths, private keys and non-example private domains.
patterns = {
    "Windows user-profile path": re.compile(r"(?i)[A-Z]:\\Users\\[^\\\s]+"),
    "Unix home path": re.compile(r"/home/[^/\s]+"),
    "private key material": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "obvious credential assignment": re.compile(r"(?i)(?:password|api[_-]?token|access[_-]?token|client[_-]?secret)\s*=\s*['\"][^'\"]{8,}['\"]"),
}

allowed_files = {
    "README-APPLY.md",
    "GIT-AND-RELEASE.md",
    "NETBOX-UPGRADE.md",
}

errors = []
for path in ROOT.rglob("*"):
    if not path.is_file():
        continue
    if path.name == "neutrality_scan.py":
        continue
    if any(part in {".git", "__pycache__", ".pytest_cache", "dist", "build"} for part in path.parts):
        continue
    if path.suffix.lower() not in {".py", ".md", ".toml", ".yaml", ".yml", ".html", ".txt", ".ps1"}:
        continue
    text = path.read_text(encoding="utf-8", errors="ignore")
    rel = path.relative_to(ROOT).as_posix()
    for label, regex in patterns.items():
        if path.name in allowed_files and label in {"Windows user-profile path", "Unix home path"}:
            continue
        match = regex.search(text)
        if match:
            # Documentation placeholders are not credentials.
            value = match.group(0)
            if "YOUR_" in value or "example" in value.lower():
                continue
            errors.append(f"{rel}: {label}: {value[:120]}")

if errors:
    print("Neutrality/security scan found potentially repository-specific data:", file=sys.stderr)
    for error in errors:
        print(f"  {error}", file=sys.stderr)
    raise SystemExit(1)

print("Neutrality/security source scan passed.")
