from netbox.jobs import JobRunner, system_job
from .constants import ALERT_SYSTEM_JOB_INTERVAL_MINUTES
from .services.alerts import run_expiry_alert_scan
from .services.status import refresh_certificate_statuses


@system_job(interval=ALERT_SYSTEM_JOB_INTERVAL_MINUTES)
class ExpiryAlertSystemJob(JobRunner):
    class Meta:
        name = "NetBox Certificates: Expiration Alert Scan"
    def run(self, *args, **kwargs):
        return run_expiry_alert_scan()


@system_job(interval=60)
class CertificateStatusSystemJob(JobRunner):
    class Meta:
        name = "NetBox Certificates: Refresh Certificate Status"
    def run(self, *args, **kwargs):
        return {"updated": refresh_certificate_statuses()}
