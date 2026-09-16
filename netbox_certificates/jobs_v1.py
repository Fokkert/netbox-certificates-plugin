from datetime import timedelta

from django.core.management import call_command
from django.utils import timezone
from netbox.jobs import JobRunner, system_job

from .models_v1 import AlertSettings
from .services.alerts_v1 import dispatch_alerts
from .services.health_v1 import refresh_health_findings


def processing_due(last_success, interval_minutes, now):
    return last_success is None or now >= last_success + timedelta(minutes=interval_minutes)


@system_job(interval=5)
class CertificateHealthAndAlertJob(JobRunner):
    class Meta:
        name = "Certificate Health and Alert Processing"

    def run(self, *args, **kwargs):
        # Existing installations may still have a 15-minute recurring job. The
        # NetBox runner uses this interval to schedule its next execution.
        self.job.interval = 5
        config, _ = AlertSettings.objects.get_or_create(pk=1)
        now = timezone.now()
        result = {"health": None, "alerts": None}
        # Refresh inexpensive stored validity state on every worker cycle.
        call_command("refresh_certificate_status", verbosity=0)
        if config.health_scan_enabled and processing_due(config.last_health_scan, config.health_scan_interval_minutes, now):
            result["health"] = refresh_health_findings()
            AlertSettings.objects.filter(pk=1).update(last_health_scan=timezone.now())
            self.logger.info("Health scan: %s active findings", result["health"]["active"])
        if processing_due(config.last_alert_evaluation, config.alert_interval_minutes, now):
            result["alerts"] = dispatch_alerts()
            AlertSettings.objects.filter(pk=1).update(last_alert_evaluation=timezone.now())
            self.logger.info("Alerts: %s", result["alerts"])
        return result
