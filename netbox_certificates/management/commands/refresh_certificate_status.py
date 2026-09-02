from django.core.management.base import BaseCommand
from netbox_certificates.services.status import refresh_certificate_statuses


class Command(BaseCommand):
    help = "Refresh stored certificate status from valid_from/valid_to timestamps."

    def handle(self, *args, **options):
        changed = refresh_certificate_statuses()
        self.stdout.write(self.style.SUCCESS(f"Refreshed certificate status; {changed} row(s) changed."))
