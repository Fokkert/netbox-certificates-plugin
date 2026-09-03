from django.core.management.base import BaseCommand

from netbox_certificates.services.alerts_v1 import dispatch_alerts


class Command(BaseCommand):
    help = "Dispatch configured certificate Health and Validity alerts."

    def handle(self, *args, **options):
        result = dispatch_alerts()
        self.stdout.write(self.style.SUCCESS(
            f"Alert dispatch complete: {result['delivered']} delivered, "
            f"{result['failed']} failed, {result['skipped']} skipped."
        ))
