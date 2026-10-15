from django.db import migrations


SUPPORTED = ["validity", "chain", "relationship", "duplicate", "service", "configuration"]


def retire_option(apps, schema_editor):
    settings_model = apps.get_model("netbox_certificates", "AlertSettings")
    rule_model = apps.get_model("netbox_certificates", "AlertRule")
    alias = schema_editor.connection.alias
    for config in settings_model.objects.using(alias).exclude(rule_id=None):
        rule = rule_model.objects.using(alias).filter(pk=config.rule_id).first()
        if rule is None:
            continue
        previous = rule.categories or []
        remaining = [value for value in previous if value != "security"]
        if not previous:
            # An empty category list used to mean every category.
            remaining = list(SUPPORTED)
        elif not remaining:
            # Do not turn a security-only rule into notifications for all problems.
            rule.enabled = False
            remaining = list(SUPPORTED)
        rule.categories = remaining
        rule.save(using=alias, update_fields=["categories", "enabled"])


class Migration(migrations.Migration):
    dependencies = [("netbox_certificates", "0029_service_certificate_checks")]
    operations = [migrations.RunPython(retire_option, migrations.RunPython.noop)]
