"""Verify Service data preservation when removing deployment metadata in CI."""
import os


def main():
    if os.environ.get("NETBOX_CONFIGURATION") != "netbox_configuration" or os.environ.get("CI") != "true":
        raise SystemExit("Only run this check on the disposable CI database.")
    os.environ["DJANGO_SETTINGS_MODULE"] = "netbox.settings"
    import django
    django.setup()
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    previous = ("netbox_certificates", "0031_activity_and_retired_models")
    current = ("netbox_certificates", "0032_remove_service_deployment_metadata")
    executor = MigrationExecutor(connection)
    executor.migrate([previous])
    apps = executor.loader.project_state([previous]).apps
    Service = apps.get_model("netbox_certificates", "Service")
    Certificate = apps.get_model("netbox_certificates", "Certificate")
    cert = Certificate.objects.create(name="migration-191-cert", fingerprint_sha256="f" * 64)
    service = Service.objects.create(
        name="migration-191-service", hostname="example.test", port=8443,
        deployment="Nginx", deployment_metadata={"namespace": "old-value"},
    )
    service.certificates.add(cert)
    before = Service.objects.filter(pk=service.pk).values().get()
    before.pop("deployment_metadata")
    executor = MigrationExecutor(connection)
    executor.migrate([current])
    apps = executor.loader.project_state([current]).apps
    Service = apps.get_model("netbox_certificates", "Service")
    Certificate = apps.get_model("netbox_certificates", "Certificate")
    assert Service.objects.filter(pk=service.pk).values().get() == before
    assert list(Service.objects.get(pk=service.pk).certificates.values_list("pk", flat=True)) == [cert.pk]
    Service.objects.filter(pk=service.pk).delete()
    Certificate.objects.filter(pk=cert.pk).delete()
    print("0031 -> 0032 removes only deployment metadata and preserves Service relationships.")


if __name__ == "__main__":
    main()
