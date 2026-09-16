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
- a 90-day expiration overview, extended when a certificate’s own alert trigger is already due
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

## Configurable checks

Alerts Configuration supplies minimum RSA size, optional maximum validity, SAN requirements, wildcard allowance, and key reuse handling. Violations create `CERTIFICATE_SETTINGS_VIOLATION` findings in category `configuration`. Settings apply to Certificates and CSRs; required SAN excludes CAs. Legacy policy definitions/assignments are inactive. Baseline weak-crypto, key-reuse, chain, and relationship findings continue independently.

## Execution

The certificate health/alert job runs in the NetBox background worker. Health scans can also be triggered manually from the UI/API or with:

```bash
python manage.py refresh_certificate_health
```

Findings that are no longer detected are marked Resolved.

The page combines expiration counts and upcoming/expired certificates with findings and their filters. Findings can be selected for bulk edit/delete. Empty finding exports display a warning. Changing a finding to acknowledged, ignored, or resolved requires the corresponding custom permission even through bulk edits or REST PATCH. Findings are created by scans; evidence is not editable.

## Reading findings (1.1.2)

The Health table shows severity and status, summary and finding code, affected and related objects, details, evidence, and last detection time. Both object columns link directly to the referenced inventory records when the viewer can view those objects; missing or inaccessible objects show a dash. Detail pages use the same permission-aware links and labeled evidence. Filtering, pagination, scans, and selected-row actions retain their existing behavior.

## Scheduling and relationship reconciliation (1.3.0)

Configure health scan and alert evaluation intervals separately in [Preferences](PREFERENCES.md). Both default to 15 minutes; scheduled scanning can be disabled while retaining manual scans. The upcoming-expiration warning window defaults to 90 days and is configurable without changing per-certificate alert timing.

Scans recalculate issuer links using signature verification and CA Basic Constraints. Stale issuer links are deactivated. Supersedes is inferred from matching SAN sets (subject when SANs are absent), CA status, and strictly earlier expiry; ties cannot form renewal cycles. This is inferred inventory succession, not proof of an external CA's renewal workflow. Old manually entered Supersedes values are replaced by these calculated relationships.
