# Certificate Policies

CertificatePolicy provides reusable, explicit certificate requirements.

## Rules

Supported 1.0 rules include:

- minimum RSA bits;
- allowed key types;
- allowed signature algorithms;
- allowed EC curves;
- maximum validity days;
- required SAN;
- wildcard allowed/forbidden;
- CA allowed/forbidden;
- permitted issuers;
- private-key reuse forbidden.

List-valued settings are JSON arrays so administrators can define the exact algorithms/issuers accepted by their environment.

## Assignments

Policies can be associated with:

- Services;
- Certificates;
- CSRs;
- Bundles.

A Service policy is applied to effective Service Certificates. A Certificate can also be assigned directly to one or more policies.

## Results

Policy failures create normal HealthFinding objects. They can therefore be:

- filtered;
- searched;
- acknowledged/ignored/resolved;
- exported;
- used as AlertRule inputs.

Policy evaluation does not rewrite certificates or private keys.
