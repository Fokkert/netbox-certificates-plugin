# Retired certificate policies

Version 1.2.0 replaces public Certificate Policy objects with five settings in **Alerts Configuration**: minimum RSA bits, optional maximum validity days, required SAN, allowed wildcards, and whether key reuse is a settings violation. These apply globally to Certificates and CSRs. CAs are exempt from the required-SAN check. Normal cryptographic security and relationship findings continue independently.

Migration `0022_global_certificate_checks` copies these five values when exactly one enabled legacy policy exists. If none or several exist, defaults apply: RSA 2048, no maximum validity, SAN required, wildcards allowed, and key reuse not treated as a configuration violation. Review the settings after upgrading; multiple differently scoped policies cannot be mapped unambiguously to one global setting. Unsupported historic RSA/validity limits also fall back to supported defaults.

Legacy rows and assignments remain in the database for audit and rollback, but are inactive. Algorithm/curve/issuer allowlists and CA eligibility are not migrated into new settings. Policy REST/GraphQL/search interfaces and permissions are retired. Existing UI policy bookmarks redirect to Alerts Configuration; policy POST operations are unavailable. The page remains superuser-only.

Alert category `policy` becomes `configuration`; explicit old policy finding codes become `CERTIFICATE_SETTINGS_VIOLATION`. Old findings resolve on the next scan if no longer detected. Existing policy-specific rule scopes are inactive: review additional alert rules because their other scopes continue to apply.
