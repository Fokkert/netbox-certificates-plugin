import extras.managers
import taggit.managers
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_certificates", "0017_service_default_related_name"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterField(
                    model_name="service",
                    name="tags",
                    field=taggit.managers.TaggableManager(
                        through="extras.TaggedItem",
                        ordering=("weight", "name"),
                        manager=extras.managers.NetBoxTaggableManager,
                        related_name="netbox_certificates_service_tagged+",
                    ),
                ),
            ],
            database_operations=[],
        ),
    ]
