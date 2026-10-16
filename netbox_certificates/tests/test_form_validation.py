"""Regression coverage using NetBox's actual model form validation chain."""
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.test import TestCase
from django.urls import reverse

from netbox_certificates.forms_v1 import AlertChannelForm, ObjectLinkForm, ServiceForm
from netbox_certificates.models import ArtifactGroup
from netbox_certificates.models_v1 import Service


class ModelFormValidationTests(TestCase):
    @classmethod
    def setUpTestData(cls):
        cls.user = get_user_model().objects.create_superuser(username="forms-admin", password="test-only")
        cls.source = ArtifactGroup.objects.create(name="Source")
        cls.target = ArtifactGroup.objects.create(name="Target")

    def service_data(self, **overrides):
        return {
            "name": "Test service", "status": "active", "service_type": "website",
            "environment": "lab", "deployment": "Nginx", "protocol": "https",
            "primary_url": "https://example.test:8443/", "criticality": "medium",
            "enabled": "on", **overrides,
        }

    def test_service_create_edit_and_stale_edit(self):
        self.client.force_login(self.user)
        prefix = "plugins:netbox_certificates:"
        response = self.client.post(reverse(prefix + "service_add"), self.service_data())
        self.assertEqual(response.status_code, 302)
        service = Service.objects.get(name="Test service")
        self.assertEqual((service.hostname, service.sni_name, service.port), ("example.test", "example.test", 8443))
        response = self.client.post(reverse(prefix + "service_edit", args=[service.pk]),
                                    self.service_data(name="Renamed service", port=443))
        self.assertEqual(response.status_code, 302)
        service.refresh_from_db()
        self.assertEqual((service.name, service.port), ("Renamed service", 443))
        form = ServiceForm(self.service_data(_init_time="1"), instance=service)
        self.assertFalse(form.is_valid())
        self.assertIn("modified since", str(form.non_field_errors()))

    def test_service_invalid_and_custom_values(self):
        for values, field in (({"port": 65536}, "port"), ({"deployment": "custom"}, "custom_deployment"),
                              ({"primary_url": "https://example.test:99999"}, "primary_url")):
            with self.subTest(values=values):
                form = ServiceForm(self.service_data(**values))
                self.assertFalse(form.is_valid())
                self.assertIn(field, form.errors)
        form = ServiceForm(self.service_data(deployment="custom", custom_deployment="Custom server", primary_url=""))
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["deployment"], "Custom server")
        self.assertEqual(form.cleaned_data["port"], 443)

    def test_service_metadata_removed_from_current_interfaces(self):
        import json
        from django.core.serializers.json import DjangoJSONEncoder
        from netbox_certificates.api.v1_serializers import ServiceSerializer
        from netbox_certificates.export_v1 import serialize_object
        from netbox_certificates.filtersets_v1 import ServiceFilterSet
        from netbox_certificates.forms_v1 import ServiceBulkEditForm, ServiceFilterForm
        from netbox_certificates.services.metadata_import import import_metadata
        from netbox_certificates.tables_v1 import ServiceTable

        service = Service.objects.create(name="Metadata removal", deployment="Nginx", hostname="example.test")
        self.assertNotIn("deployment_metadata", ServiceSerializer().fields)
        self.assertNotIn("deployment_metadata", ServiceTable.base_columns)
        self.assertNotIn("deployment_metadata", ServiceFilterSet.base_filters)
        for form in (ServiceForm, ServiceBulkEditForm, ServiceFilterForm):
            self.assertNotIn("deployment_metadata", form().fields)
        self.client.force_login(self.user)
        table_name = ServiceTable([]).name
        self.user.config.set(f"tables.{table_name}.columns", ["name", "deployment_metadata"], commit=True)
        self.user.config.set(f"tables.{table_name}.ordering", ["deployment_metadata"], commit=True)
        for path in ("/plugins/ssl-certificates/services/", f"/plugins/ssl-certificates/services/{service.pk}/",
                     f"/plugins/ssl-certificates/services/{service.pk}/edit/", "/api/plugins/ssl-certificates/services/"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertNotContains(response, "deployment_metadata")
        row = serialize_object(service, self.user)
        self.assertNotIn("deployment_metadata", row["attributes"])
        # Older metadata exports still restore the current Service fields.
        row["attributes"]["deployment_metadata"] = {"namespace": "retired"}
        service.delete()
        result = import_metadata(json.dumps([row], cls=DjangoJSONEncoder).encode(), self.user)
        self.assertEqual(result["imported"], 1)
        restored = Service.objects.get(name="Metadata removal")
        self.assertEqual((restored.deployment, restored.hostname), ("Nginx", "example.test"))

    def test_object_links_validate_visibility_and_missing_objects(self):
        content_type = ContentType.objects.get_for_model(ArtifactGroup).pk
        data = {"source_type": content_type, "source_object_id": self.source.pk,
                "target_type": content_type, "target_object_id": self.target.pk,
                "relationship": "related", "enabled": "on"}
        form = ObjectLinkForm(data, user=self.user)
        self.assertTrue(form.is_valid(), form.errors)
        link = form.save()
        edit = ObjectLinkForm({**data, "label": "Updated"}, instance=link, user=self.user)
        self.assertTrue(edit.is_valid(), edit.errors)
        edit.save()
        for user, target in ((self.user, 999999), (get_user_model().objects.create_user(username="no-access"), self.target.pk)):
            form = ObjectLinkForm({**data, "target_object_id": target}, user=user)
            self.assertFalse(form.is_valid())
            self.assertIn("target_object_id", form.errors)
        for field in ("source_type", "target_type"):
            form = ObjectLinkForm({**data, field: ""}, user=self.user)
            self.assertFalse(form.is_valid())
            self.assertIn(field, form.errors)

    def test_alert_channels_create_edit_and_reject_invalid_values(self):
        data = {"name": "Test channel", "channel_type": "webhook", "smtp_port": 587,
                "webhook_method": "POST", "webhook_url": "https://example.test/hooks",
                "subject_prefix": "[Test]", "webhook_headers": "{}"}
        form = AlertChannelForm(data)
        self.assertTrue(form.is_valid(), form.errors)
        channel = form.save()
        form = AlertChannelForm({**data, "webhook_method": "GET"}, instance=channel)
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.save().webhook_method, "GET")
        for overrides, field in (({"webhook_url": ""}, "webhook_url"),
                                 ({"channel_type": "email", "recipients": '["invalid"]', "smtp_host": "mail.example.test"}, "recipients"),
                                 ({"smtp_port": 65536}, "smtp_port")):
            form = AlertChannelForm({**data, **overrides})
            self.assertFalse(form.is_valid())
            self.assertIn(field, form.errors)
