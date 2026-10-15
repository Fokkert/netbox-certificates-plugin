"""Verify typed-group and naming migrations on disposable CI data only."""
import os


def main():
    if os.environ.get("NETBOX_CONFIGURATION") != "netbox_configuration" or os.environ.get("CI") != "true":
        raise SystemExit("Only run this check on the disposable CI database.")
    os.environ["DJANGO_SETTINGS_MODULE"] = "netbox.settings"
    import django
    django.setup()
    from django.db import connection
    from django.db.migrations.executor import MigrationExecutor

    old = ("netbox_certificates", "0025_alertrule_statuses_default")
    target = ("netbox_certificates", "0027_readable_generated_names")
    executor = MigrationExecutor(connection)
    executor.migrate([old])
    apps = executor.loader.project_state([old]).apps
    Group = apps.get_model("netbox_certificates", "ArtifactGroup")
    Cert = apps.get_model("netbox_certificates", "Certificate")
    Key = apps.get_model("netbox_certificates", "PrivateKey")
    root = Group.objects.create(name="migration-root")
    typed = Group.objects.create(name="migration-certificates", parent=root)
    mixed = Group.objects.create(name="migration-mixed", parent=root)
    subject = "1.2.840.113549.1.9.1=admin@example.test,O=PKI"
    cert = Cert.objects.create(name=subject, subject=subject, subject_alternative_names=["DNS:pmg.example.test"],
                               material="migration-fixture-unchanged", fingerprint_sha256="a" * 64,
                               public_key_fingerprint="b" * 64)
    custom = Cert.objects.create(name="Preserve custom name", subject=subject,
                                 subject_alternative_names=["DNS:custom.example.test"], material="unchanged-custom",
                                 fingerprint_sha256="c" * 64, public_key_fingerprint="d" * 64)
    key = Key.objects.create(name="Private Key " + "b" * 12, public_key_fingerprint="b" * 64,
                             material_sha256="e" * 64, encrypted_material=b"unchanged-encrypted-fixture")
    cert.groups.add(typed, mixed)
    key.groups.add(mixed)
    before = list(Cert.objects.filter(pk__in=[cert.pk, custom.pk]).order_by("pk").values())
    executor = MigrationExecutor(connection)
    executor.migrate([target])
    apps = executor.loader.project_state([target]).apps
    Group = apps.get_model("netbox_certificates", "ArtifactGroup")
    Cert = apps.get_model("netbox_certificates", "Certificate")
    Key = apps.get_model("netbox_certificates", "PrivateKey")
    assert Group.objects.get(pk=root.pk).group_type == "group"
    assert Group.objects.get(pk=typed.pk).group_type == "certificate"
    assert Group.objects.get(pk=mixed.pk).group_type == "mixed"
    assert set(Cert.objects.get(pk=cert.pk).groups.values_list("pk", flat=True)) == {typed.pk, mixed.pk}
    assert set(Key.objects.get(pk=key.pk).groups.values_list("pk", flat=True)) == {mixed.pk}
    assert Cert.objects.get(pk=cert.pk).name == "pmg.example.test"
    assert Cert.objects.get(pk=custom.pk).name == "Preserve custom name"
    assert Key.objects.get(pk=key.pk).name == "pmg.example.test Private key"
    assert bytes(Key.objects.get(pk=key.pk).encrypted_material) == b"unchanged-encrypted-fixture"
    after = list(Cert.objects.filter(pk__in=[cert.pk, custom.pk]).order_by("pk").values())
    for row in before + after:
        row.pop("name")
    assert before == after, "Naming repair changed certificate data beyond the display name."
    Cert.objects.filter(pk__in=[cert.pk, custom.pk]).delete()
    Key.objects.filter(pk=key.pk).delete()
    Group.objects.filter(pk__in=[root.pk, typed.pk, mixed.pk]).delete()
    print("0025 -> 0027 preserves group memberships, material, and custom names.")


if __name__ == "__main__":
    main()
