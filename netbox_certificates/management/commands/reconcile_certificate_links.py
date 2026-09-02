from django.core.management.base import BaseCommand
from netbox_certificates.services.linker import reconcile_links


class Command(BaseCommand):
    help = "Rebuild automatic links among certificates, CSRs, private keys, and certificate issuers."

    def handle(self, *args, **options):
        reconcile_links()
        self.stdout.write(self.style.SUCCESS("Certificate links reconciled."))
