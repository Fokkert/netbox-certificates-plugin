# Compatibility

## 0.4.11

| NetBox | Support level |
| --- | --- |
| 4.5.9 | Fully live-validated and supported. |
| 4.5.10 | Declared supported by PluginConfig; same 4.5 patch line, but not yet exercised with the same exhaustive live matrix as 4.5.9. |
| <= 4.5.8 | Unsupported and rejected by `min_version = "4.5.9"`. NetBox 4.5.9 includes a fix for constrained ObjectPermission scope filtering used by this plugin. |
| >= 4.6.0 | Unsupported and rejected by `max_version = "4.5.10"`; NetBox 4.6 upgrades to Django 6.0 and changes/deprecates plugin APIs, requiring a dedicated compatibility release. |

Python 3.12+ is required by the package. Production validation for 0.4.11 was performed on NetBox 4.5.9 with Python 3.12.
