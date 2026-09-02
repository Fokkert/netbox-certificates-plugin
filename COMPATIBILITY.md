# Compatibility

## 0.5.0

| NetBox | Support level |
| --- | --- |
| 4.5.9 | Declared supported; same compatibility target as 0.4.11. Run staging/live validation before production promotion of 0.5.0. |
| 4.5.10 | Declared supported by `PluginConfig`; same NetBox 4.5 patch line. |
| <= 4.5.8 | Unsupported and rejected by `min_version = "4.5.9"`. |
| >= 4.6.0 | Unsupported and rejected by `max_version = "4.5.10"`; a dedicated compatibility release is required. |

Python 3.12+ is required by the package. The 0.5.0 release does not change the NetBox compatibility gate.

The release changes application behavior only; it does not alter the database schema. The existing `CertificateAuthority` data model and CA-chain relationships are retained.
