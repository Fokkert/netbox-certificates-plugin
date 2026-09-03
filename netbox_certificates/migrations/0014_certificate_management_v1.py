import django.db.models.deletion
import extras.managers
import taggit.managers
import utilities.json
from django.db import migrations, models
from django.utils import timezone



def default_alert_statuses():
    return ["active"]



def _base_fields():
    return [
        (
            "id",
            models.BigAutoField(
                auto_created=True,
                primary_key=True,
                serialize=False,
                verbose_name="ID",
            ),
        ),
        (
            "created",
            models.DateTimeField(
                auto_now_add=True,
                blank=True,
                null=True,
                verbose_name="created",
            ),
        ),
        (
            "last_updated",
            models.DateTimeField(
                auto_now=True,
                blank=True,
                null=True,
                verbose_name="last updated",
            ),
        ),
        (
            "custom_field_data",
            models.JSONField(
                blank=True,
                default=dict,
                encoder=utilities.json.CustomFieldJSONEncoder,
            ),
        ),
        (
            "description",
            models.CharField(blank=True, max_length=200),
        ),
        (
            "comments",
            models.TextField(blank=True),
        ),
        (
            "owner",
            models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.PROTECT,
                to="users.owner",
            ),
        ),
        (
            "tags",
            taggit.managers.TaggableManager(
                through="extras.TaggedItem",
                to="extras.Tag",
                ordering=("weight", "name"),
                manager=extras.managers.NetBoxTaggableManager,
            ),
        ),
    ]


class Migration(migrations.Migration):

    dependencies = [
        ("netbox_certificates", "0013_root_authorities_and_bundle_status"),
    ]

    operations = [
        migrations.CreateModel(
            name="CertificatePolicy",
            fields=_base_fields() + [
                ("name", models.CharField(max_length=120, unique=True)),
                ("enabled", models.BooleanField(default=True)),
                ("minimum_rsa_bits", models.PositiveIntegerField(default=2048)),
                ("allowed_key_types", models.JSONField(blank=True, default=list)),
                ("allowed_signature_algorithms", models.JSONField(blank=True, default=list)),
                ("allowed_curves", models.JSONField(blank=True, default=list)),
                ("max_validity_days", models.PositiveIntegerField(blank=True, null=True)),
                ("require_san", models.BooleanField(default=True)),
                ("allow_wildcards", models.BooleanField(default=True)),
                ("allow_ca", models.BooleanField(default=False)),
                ("allowed_issuers", models.JSONField(blank=True, default=list)),
                ("forbid_key_reuse", models.BooleanField(default=False)),
                (
                    "bundles",
                    models.ManyToManyField(
                        blank=True,
                        related_name="certificate_policies",
                        to="netbox_certificates.bundle",
                    ),
                ),
                (
                    "certificates",
                    models.ManyToManyField(
                        blank=True,
                        related_name="certificate_policies",
                        to="netbox_certificates.certificate",
                    ),
                ),
                (
                    "csrs",
                    models.ManyToManyField(
                        blank=True,
                        related_name="certificate_policies",
                        to="netbox_certificates.csr",
                    ),
                ),
            ],
            options={
                "ordering": ("name",),
                "permissions": (
                    ("archive_export_certificatepolicy", "Can archive-export certificate policies"),
                ),
            },
        ),
        migrations.CreateModel(
            name="Service",
            fields=_base_fields() + [
                ("name", models.CharField(max_length=160, unique=True)),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("active", "Active"),
                            ("planned", "Planned"),
                            ("maintenance", "Maintenance"),
                            ("deprecated", "Deprecated"),
                            ("offline", "Offline"),
                        ],
                        default="active",
                        max_length=32,
                    ),
                ),
                (
                    "service_type",
                    models.CharField(
                        choices=[
                            ("web_server", "Web Server"),
                            ("website", "Website"),
                            ("repository", "Repository"),
                            ("container_registry", "Container Registry"),
                            ("api", "API"),
                            ("api_gateway", "API Gateway"),
                            ("reverse_proxy", "Reverse Proxy"),
                            ("load_balancer", "Load Balancer"),
                            ("kubernetes", "Kubernetes"),
                            ("openshift", "OpenShift"),
                            ("ci_cd", "CI/CD"),
                            ("git_service", "Git Service"),
                            ("artifact_repository", "Artifact Repository"),
                            ("mail_server", "Mail Server"),
                            ("database", "Database"),
                            ("directory", "Directory / LDAP"),
                            ("vpn", "VPN"),
                            ("remote_access", "Remote Access"),
                            ("monitoring", "Monitoring"),
                            ("message_broker", "Message Broker"),
                            ("storage", "Storage"),
                            ("identity", "Identity Service"),
                            ("internal_application", "Internal Application"),
                            ("external_application", "External Application"),
                            ("other", "Other"),
                        ],
                        default="website",
                        max_length=64,
                    ),
                ),
                ("other_type", models.CharField(blank=True, max_length=120)),
                (
                    "deployment",
                    models.CharField(
                        default="Generic TLS Endpoint",
                        help_text="Deployment technology or pattern. Common values are suggested by the UI; custom values are allowed.",
                        max_length=120,
                    ),
                ),
                (
                    "deployment_metadata",
                    models.JSONField(
                        blank=True,
                        default=dict,
                        help_text="Optional deployment-specific metadata such as namespace, secret name, virtual host, ingress, or configuration reference.",
                    ),
                ),
                (
                    "environment",
                    models.CharField(
                        choices=[
                            ("production", "Production"),
                            ("staging", "Staging"),
                            ("development", "Development"),
                            ("testing", "Testing"),
                            ("lab", "Lab"),
                            ("other", "Other"),
                        ],
                        default="production",
                        max_length=32,
                    ),
                ),
                ("protocol", models.CharField(default="https", max_length=32)),
                ("primary_url", models.URLField(blank=True, max_length=500)),
                ("additional_urls", models.JSONField(blank=True, default=list)),
                ("hostname", models.CharField(blank=True, max_length=255)),
                ("port", models.PositiveIntegerField(default=443)),
                ("sni_name", models.CharField(blank=True, max_length=255)),
                (
                    "criticality",
                    models.CharField(
                        choices=[
                            ("low", "Low"),
                            ("medium", "Medium"),
                            ("high", "High"),
                            ("critical", "Critical"),
                        ],
                        default="medium",
                        max_length=32,
                    ),
                ),
                ("external_reference", models.CharField(blank=True, max_length=200)),
                ("contact", models.CharField(blank=True, max_length=200)),
                ("enabled", models.BooleanField(default=True)),
                (
                    "policy",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.PROTECT,
                        related_name="services",
                        to="netbox_certificates.certificatepolicy",
                    ),
                ),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        related_name="services",
                        to="netbox_certificates.artifactgroup",
                    ),
                ),
                (
                    "certificates",
                    models.ManyToManyField(
                        blank=True,
                        related_name="services",
                        to="netbox_certificates.certificate",
                    ),
                ),
                (
                    "private_keys",
                    models.ManyToManyField(
                        blank=True,
                        related_name="services",
                        to="netbox_certificates.privatekey",
                    ),
                ),
                (
                    "csrs",
                    models.ManyToManyField(
                        blank=True,
                        related_name="services",
                        to="netbox_certificates.csr",
                    ),
                ),
                (
                    "bundles",
                    models.ManyToManyField(
                        blank=True,
                        related_name="services",
                        to="netbox_certificates.bundle",
                    ),
                ),
            ],
            options={
                "ordering": ("name",),
                "permissions": (
                    ("archive_export_service", "Can archive-export services"),
                ),
            },
        ),
        migrations.CreateModel(
            name="ObjectLink",
            fields=_base_fields() + [
                ("source_object_id", models.PositiveBigIntegerField()),
                ("target_object_id", models.PositiveBigIntegerField()),
                ("relationship", models.CharField(default="related", max_length=80)),
                ("label", models.CharField(blank=True, max_length=160)),
                ("enabled", models.BooleanField(default=True)),
                (
                    "automatic",
                    models.BooleanField(
                        default=False,
                        help_text="True for relationships maintained by the internal cryptographic reconciliation engine.",
                    ),
                ),
                (
                    "source_type",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to="contenttypes.contenttype",
                    ),
                ),
                (
                    "target_type",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to="contenttypes.contenttype",
                    ),
                ),
            ],
            options={
                "ordering": ("source_type_id", "source_object_id", "target_type_id", "target_object_id"),
                "permissions": (
                    ("archive_export_objectlink", "Can archive-export object links"),
                ),
            },
        ),
        migrations.AddConstraint(
            model_name="objectlink",
            constraint=models.UniqueConstraint(
                fields=("source_type", "source_object_id", "target_type", "target_object_id", "relationship"),
                name="netbox_certificates_v1_objectlink_unique",
            ),
        ),
        migrations.AddIndex(
            model_name="objectlink",
            index=models.Index(fields=["source_type", "source_object_id"], name="nbcert_v1_link_src_idx"),
        ),
        migrations.AddIndex(
            model_name="objectlink",
            index=models.Index(fields=["target_type", "target_object_id"], name="nbcert_v1_link_dst_idx"),
        ),
        migrations.CreateModel(
            name="HealthFinding",
            fields=_base_fields() + [
                ("code", models.CharField(max_length=120)),
                ("category", models.CharField(max_length=80)),
                (
                    "severity",
                    models.CharField(
                        choices=[
                            ("info", "Info"),
                            ("warning", "Warning"),
                            ("medium", "Medium"),
                            ("high", "High"),
                            ("critical", "Critical"),
                        ],
                        max_length=32,
                    ),
                ),
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("active", "Active"),
                            ("acknowledged", "Acknowledged"),
                            ("ignored", "Ignored"),
                            ("resolved", "Resolved"),
                        ],
                        default="active",
                        max_length=32,
                    ),
                ),
                ("object_id", models.PositiveBigIntegerField()),
                ("related_object_id", models.PositiveBigIntegerField(blank=True, null=True)),
                ("summary", models.CharField(max_length=300)),
                ("details", models.JSONField(blank=True, default=dict)),
                ("evidence", models.JSONField(blank=True, default=dict)),
                ("fingerprint", models.CharField(max_length=64, unique=True)),
                ("first_detected", models.DateTimeField(default=timezone.now)),
                ("last_detected", models.DateTimeField(default=timezone.now)),
                ("resolved_at", models.DateTimeField(blank=True, null=True)),
                (
                    "object_type",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="+",
                        to="contenttypes.contenttype",
                    ),
                ),
                (
                    "related_type",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="+",
                        to="contenttypes.contenttype",
                    ),
                ),
            ],
            options={
                "ordering": ("status", "-severity", "-last_detected"),
                "permissions": (
                    ("run_healthscan_healthfinding", "Can run certificate health scans"),
                    ("acknowledge_healthfinding", "Can acknowledge health findings"),
                    ("ignore_healthfinding", "Can ignore health findings"),
                    ("resolve_healthfinding", "Can resolve health findings"),
                    ("archive_export_healthfinding", "Can archive-export health findings"),
                ),
            },
        ),
        migrations.AddIndex(
            model_name="healthfinding",
            index=models.Index(fields=["object_type", "object_id"], name="nbcert_v1_health_obj_idx"),
        ),
        migrations.AddIndex(
            model_name="healthfinding",
            index=models.Index(fields=["status", "severity"], name="nbcert_v1_health_state_idx"),
        ),
        migrations.CreateModel(
            name="AlertChannel",
            fields=_base_fields() + [
                ("name", models.CharField(max_length=120, unique=True)),
                ("enabled", models.BooleanField(default=True)),
                (
                    "channel_type",
                    models.CharField(
                        choices=[("email", "Email"), ("webhook", "Webhook")],
                        max_length=32,
                    ),
                ),
                ("recipients", models.JSONField(blank=True, default=list)),
                ("smtp_host", models.CharField(blank=True, max_length=255)),
                ("smtp_port", models.PositiveIntegerField(default=587)),
                ("smtp_username", models.CharField(blank=True, max_length=255)),
                ("smtp_password_encrypted", models.TextField(blank=True)),
                ("smtp_use_tls", models.BooleanField(default=True)),
                ("smtp_use_ssl", models.BooleanField(default=False)),
                ("from_email", models.EmailField(blank=True, max_length=254)),
                ("webhook_url_encrypted", models.TextField(blank=True)),
                ("webhook_headers_encrypted", models.TextField(blank=True)),
                ("subject_prefix", models.CharField(default="[NetBox Certificates]", max_length=120)),
            ],
            options={
                "ordering": ("name",),
                "permissions": (
                    ("test_alertchannel", "Can test alert channels"),
                    ("archive_export_alertchannel", "Can archive-export alert channels"),
                ),
            },
        ),
        migrations.CreateModel(
            name="AlertRule",
            fields=_base_fields() + [
                ("name", models.CharField(max_length=120, unique=True)),
                ("enabled", models.BooleanField(default=True)),
                ("finding_codes", models.JSONField(blank=True, default=list)),
                ("categories", models.JSONField(blank=True, default=list)),
                ("severities", models.JSONField(blank=True, default=list)),
                ("object_types", models.JSONField(blank=True, default=list)),
                ("tag_names", models.JSONField(blank=True, default=list)),
                ("owner_ids", models.JSONField(blank=True, default=list)),
                ("expiration_days", models.PositiveIntegerField(blank=True, null=True)),
                (
                    "statuses",
                    models.JSONField(
                        blank=True,
                        default=default_alert_statuses,
                    ),
                ),
                ("cooldown_minutes", models.PositiveIntegerField(default=60)),
                ("repeat_minutes", models.PositiveIntegerField(default=1440)),
                ("notify_on_recovery", models.BooleanField(default=False)),
                (
                    "channels",
                    models.ManyToManyField(
                        blank=True,
                        related_name="rules",
                        to="netbox_certificates.alertchannel",
                    ),
                ),
                (
                    "services",
                    models.ManyToManyField(
                        blank=True,
                        related_name="alert_rules",
                        to="netbox_certificates.service",
                    ),
                ),
                (
                    "policies",
                    models.ManyToManyField(
                        blank=True,
                        related_name="alert_rules",
                        to="netbox_certificates.certificatepolicy",
                    ),
                ),
                (
                    "groups",
                    models.ManyToManyField(
                        blank=True,
                        related_name="alert_rules",
                        to="netbox_certificates.artifactgroup",
                    ),
                ),
            ],
            options={
                "ordering": ("name",),
                "permissions": (
                    ("test_alertrule", "Can test alert rules"),
                    ("archive_export_alertrule", "Can archive-export alert rules"),
                ),
            },
        ),
        migrations.CreateModel(
            name="AlertEvent",
            fields=_base_fields() + [
                (
                    "status",
                    models.CharField(
                        choices=[
                            ("delivered", "Delivered"),
                            ("failed", "Failed"),
                            ("skipped", "Skipped"),
                        ],
                        max_length=32,
                    ),
                ),
                ("delivered_at", models.DateTimeField(blank=True, null=True)),
                ("error", models.TextField(blank=True)),
                ("payload_summary", models.JSONField(blank=True, default=dict)),
                (
                    "rule",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="events",
                        to="netbox_certificates.alertrule",
                    ),
                ),
                (
                    "channel",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="events",
                        to="netbox_certificates.alertchannel",
                    ),
                ),
                (
                    "finding",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="alert_events",
                        to="netbox_certificates.healthfinding",
                    ),
                ),
            ],
            options={
                "ordering": ("-created",),
                "permissions": (
                    ("archive_export_alertevent", "Can archive-export alert events"),
                ),
            },
        ),
    ]
