from django.core.management.base import BaseCommand

from netbox_certificates.services.health_v1 import refresh_health_findings


class Command(BaseCommand):
    help = "Recompute certificate-management Health and Validity findings."

    def handle(self, *args, **options):
        result = refresh_health_findings()
        self.stdout.write(self.style.SUCCESS(
            f"Health scan complete: {result['active']} active findings, {result['total']} total finding records."
        ))
