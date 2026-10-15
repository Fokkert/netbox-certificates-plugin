from django.db import migrations, models


TYPES = [("group", "Groups"), ("certificate", "Certificates"), ("privatekey", "Private Keys"),
         ("csr", "CSRs"), ("bundle", "Bundles"), ("service", "Services"), ("mixed", "Mixed (legacy)")]


def classify_groups(apps, schema_editor):
    Group = apps.get_model("netbox_certificates", "ArtifactGroup")
    alias = schema_editor.connection.alias
    for group in Group.objects.using(alias).iterator():
        kinds = []
        if Group.objects.using(alias).filter(parent_id=group.pk).exists():
            kinds.append("group")
        for kind, model in (("certificate", "Certificate"), ("privatekey", "PrivateKey"),
                            ("csr", "CSR"), ("bundle", "Bundle"), ("service", "Service")):
            if apps.get_model("netbox_certificates", model).objects.using(alias).filter(groups=group.pk).exists():
                kinds.append(kind)
        value = kinds[0] if len(kinds) == 1 else "mixed" if kinds else "group"
        Group.objects.using(alias).filter(pk=group.pk).update(group_type=value)


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0025_alertrule_statuses_default")]
    operations = [
        migrations.AddField(model_name="artifactgroup", name="group_type",
                            field=models.CharField(max_length=16, choices=TYPES, default="mixed")),
        migrations.RunPython(classify_groups, migrations.RunPython.noop),
        migrations.AlterField(model_name="artifactgroup", name="group_type",
                              field=models.CharField(max_length=16, choices=TYPES, default="group")),
    ]
