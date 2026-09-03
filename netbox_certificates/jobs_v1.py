from django.core.management import call_command
from netbox.jobs import JobRunner, system_job

from .services.alerts_v1 import dispatch_alerts
from .services.health_v1 import refresh_health_findings


@system_job(interval=15)
class CertificateHealthAndAlertJob(JobRunner):
    class Meta:
        name = "Certificate Health and Alert Processing"

    def run(self, *args, **kwargs):
        # Keep the established certificate validity/status fields current without
        # registering the pre-1.0 expiration-only alert worker.
        call_command("refresh_certificate_status", verbosity=0)
        result = refresh_health_findings()
        delivery = dispatch_alerts()
        self.logger.info(
            "Certificate health scan: %s active findings; alerts: %s delivered, %s failed, %s skipped",
            result["active"],
            delivery["delivered"],
            delivery["failed"],
            delivery["skipped"],
        )
        return {"health": result, "alerts": delivery}
