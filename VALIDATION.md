# Validation

The update package performs source-level validation after applying the release files.

## Automated checks

- 0.5.0 source baseline verification
- release metadata verification
- 1.0 model and API integration checks
- static feature contract tests
- Python source compilation
- `git diff --check`
- repository neutrality/security scan
- removed route/API registration checks

The contract tests cover Services, many-to-many cryptographic relationships, ObjectLinks, CA Certificate views, Health checks, Alert models, export filtering, manifests, global search, migrations, and navigation.

## NetBox runtime validation

Before production deployment, run against NetBox 4.5.9 or 4.5.10 with PostgreSQL and Redis:

```bash
python manage.py check
python manage.py migrate --check
python manage.py makemigrations --check --dry-run netbox_certificates
```

Recommended smoke tests:

1. create a Service and link a Certificate
2. export a filtered Certificate list with **Export Material**
3. run a Health scan
4. verify an Alert Channel test
5. verify existing Certificates, Keys, CSRs, Bundles, and Groups are present after migration
