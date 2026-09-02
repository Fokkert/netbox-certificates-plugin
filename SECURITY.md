# Security Policy

## Supported versions

For release 0.4.11, the declared NetBox range is 4.5.9-4.5.10.

## Reporting a vulnerability

Do not post private-key material, Fernet encryption keys, API tokens, SMTP credentials, webhook tokens, or other secrets in a public GitHub issue.

Enable GitHub **Private vulnerability reporting** for the repository and use it for security reports. Until configured, contact the repository maintainer privately through the account/organization that owns the repository.

## Security invariants

- private-key plaintext is encrypted at rest and excluded from ordinary serializers;
- private-key material API access requires superuser status and a write-enabled token;
- CSR generation that creates a private key is superuser-only through the API;
- Bundle export containing a private key and all PFX exports are superuser-only through the API;
- cryptographically mismatched primary artifacts are rejected atomically;
- sensitive downloads should not be cached.
