# Health and Validity

HealthFinding stores certificate-management problems as persistent NetBox objects.

## Finding fields

- code
- category
- severity
- status
- affected object
- optional related object
- summary
- details and evidence
- stable fingerprint
- first/last detection time
- resolution time
- owner, tags, custom fields, description, comments

Statuses:

```text
Active
Acknowledged
Ignored
Resolved
```

Severities:

```text
Info
Warning
Medium
High
Critical
```

## Certificate checks

- expired
- not yet valid
- configurable expiration horizon
- weak key parameters
- weak signature algorithms
- missing issuer
- ambiguous issuer
- issuer is not a CA
- expired/not-yet-valid issuer
- invalid issuer signature
- unresolved root CA
- invalid self-signed root
- chain loops and excessive depth

## Duplicate and key checks

- duplicate Certificates
- duplicate Private Keys
- duplicate CSRs
- duplicate Bundle identities
- weak RSA or elliptic-curve keys
- DSA private keys
- orphaned private keys

## Bundle checks

Bundle primary artifacts are checked for completeness and matching public-key identity.

## Service checks

The engine validates Service hostname, SNI, and URL identities against Certificate SANs, evaluates key/CSR relationships, detects key reuse across Services, and reports suspicious non-wildcard certificate sharing.

Wildcard DNS matching covers a single label. For example, `*.example.com` matches `www.example.com` but not `a.b.example.com`.

## Policy checks

Certificate Policies evaluate key size/type, signature algorithm, EC curve, validity, SAN requirements, wildcard rules, CA eligibility, issuer restrictions, and private-key reuse.

## Execution

The certificate health/alert job runs in the NetBox background worker. Health scans can also be triggered manually from the UI/API or with:

```bash
python manage.py refresh_certificate_health
```

Findings that are no longer detected are marked Resolved.
