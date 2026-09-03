# Compatibility

## 1.0.0

| Component | Supported |
| --- | --- |
| NetBox | 4.5.9, 4.5.10 |
| Python | 3.12+ |
| PostgreSQL | The version supported by the selected NetBox 4.5 installation |
| `cryptography` | 42+ |
| `requests` | 2.32+ |
| Upgrade source | 0.5.0 |

The plugin enforces `PluginConfig.min_version = "4.5.9"` and `max_version = "4.5.10"`.

NetBox 4.6 and later are not accepted by 1.0.0. A future compatibility release should validate migrations, generic views, GraphQL, background jobs, permission behavior and filter contracts against the target NetBox version before raising the maximum version.
