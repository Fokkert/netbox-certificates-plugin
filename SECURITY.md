# Security

## Sensitive material

Private-key material is encrypted at rest with the Fernet key configured under:

```python
PLUGINS_CONFIG["netbox_certificates"]["encryption_key"]
```

1.0 also encrypts SMTP passwords and webhook configuration.

Do not rotate or replace the Fernet key without a migration procedure.

## Exposure boundaries

Raw private-key material and alert secrets are excluded from:

- normal list/detail metadata serializers;
- GraphQL metadata;
- global search indexes;
- ordinary metadata archives;
- filters.

Authorized direct/material exports may contain decrypted private keys. Treat those downloaded files/archives as secrets.

## Reporting

Report suspected vulnerabilities through the repository's security-reporting mechanism or maintainers rather than publishing exploit details in a public issue before coordination.
