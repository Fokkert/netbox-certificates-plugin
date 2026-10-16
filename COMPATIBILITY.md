# Compatibility

## 1.9.1

| Component | Supported |
| --- | --- |
| NetBox | 4.5.9, 4.5.10 |
| Python | 3.12+ |
| PostgreSQL | The version supported by the selected NetBox 4.5 installation |
| `cryptography` | 42+ |
| `requests` | 2.32+ |
| Upgrade source | Existing installations; all earlier migrations retained |

The plugin enforces `PluginConfig.min_version = "4.5.9"` and `max_version = "4.5.10"`.

NetBox 4.6 and later are not accepted by this release. A future compatibility release should validate migrations, generic views, GraphQL, background jobs, permission behavior and filter contracts against the target NetBox version before raising the maximum version.

The v1.9.1 release passed GitHub Actions checks against NetBox 4.5.9 and 4.5.10, including PostgreSQL migrations, model/migration consistency, Django system checks, upgrade-data checks, and plugin integration tests. See [VALIDATION.md](VALIDATION.md) for coverage and limits.
