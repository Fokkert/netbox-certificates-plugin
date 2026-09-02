# Validation Notes - 0.5.0

0.5.0 is a feature release for bulk import/export and Certificate Authority UI retirement.

Source-level validation performed for this update includes:

- Python syntax compilation for all new/replaced Python modules;
- release-contract/static tests for the four material-export routes and permission boundaries;
- static verification that the Certificate Authorities navigation item is removed while the `CertificateAuthority` model, certificate `authority` foreign key, root-CA service, and read-only API route remain;
- static verification that batch import supports multiple archive inputs and groups loose Bundle candidates by public-key fingerprint;
- archive integrity verification for the supplied update ZIP.

Production/live NetBox integration validation is still required before publishing 0.5.0. In particular, validate:

1. importing ten unrelated certificates in one request;
2. importing five independent Bundle archives in one request;
3. importing multiple loose certificate/key/CSR Bundle sets;
4. bulk Certificate and CSR export under constrained ObjectPermissions;
5. bulk Private Key export under the intended `download_privatekey` scope;
6. bulk Bundle export for public-only and private-key-containing Bundles;
7. legacy Certificate Authority URLs redirecting to Certificates without breaking CA-chain resolution;
8. `manage.py check`, background jobs, and expiration-alert delivery after upgrade.

No database migration is expected for 0.5.0 because the CA identity model and relationships remain unchanged.
