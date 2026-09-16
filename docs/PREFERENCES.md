# Preferences

Open **SSL Certificates → Overview → Preferences**. Only NetBox superusers can read or change these global settings. Notification destinations, transport credentials, TLS verification, certificate checks, repeat timing, and sample-delivery buttons remain in **Alerts Configuration**.

| Setting | Default | Accepted values / effect |
| --- | --- | --- |
| Scheduled health scans | Enabled | Disabling leaves manual scans available; alerts continue using stored findings |
| Health scan frequency | 15 minutes | 5, 15, 30, 60, 180, 360, 720, or 1440 minutes |
| Alert evaluation frequency | 15 minutes | Same intervals, independent of scanning |
| Upcoming-expiration findings | 90 days | 30–3650 days; per-certificate alert triggers remain independent |
| Include certificate chains by default | Enabled | Initial value for object imports; individual requests can override |
| Preserve single-bundle source archives | Enabled | Initial value for supported archive imports |
| Default RSA size for new CSR keys | 3072 bits | 2048, 3072, 4096, or 8192; existing keys are unchanged |

NetBox's worker checks schedules every five minutes. Intervals are measured from the last successful scheduled operation; queue delays and scan duration can delay the next run. Failed scans do not advance their success timestamp or send alerts based on that failed run. An existing 15-minute recurring job switches to the five-minute check cycle after its next execution. Keep `netbox-rq` running.

The page displays last successful scheduled scan and alert evaluation times. Manual health scans do not change the scheduled timestamp. Saving preferences preserves alert configuration and worker timestamps.

REST: `GET`, `PATCH`, and `PUT /api/plugins/ssl-certificates/preferences/`. PATCH and PUT update supplied fields, preserving omitted settings, and require a superuser with a write-enabled NetBox API token. Invalid intervals/key sizes/ranges return HTTP 400. Timestamps are read-only. See [API](API.md).
