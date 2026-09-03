from django.contrib.contenttypes.models import ContentType
from netbox.plugins import PluginTemplateExtension

from .models_v1 import ObjectLink


PLUGIN_RELATIONSHIP_MODELS = [
    "netbox_certificates.artifactgroup",
    "netbox_certificates.service",
    "netbox_certificates.bundle",
    "netbox_certificates.certificate",
    "netbox_certificates.privatekey",
    "netbox_certificates.csr",
    "netbox_certificates.certificatepolicy",
    "netbox_certificates.healthfinding",
    "netbox_certificates.alertrule",
    "netbox_certificates.alertchannel",
    "netbox_certificates.alertevent",
]

# Reciprocal ObjectLink visibility on common native NetBox inventory objects.
# Unknown/uninstalled models are harmless because template extensions are
# resolved only for models which exist in the running NetBox installation.
NATIVE_LINK_MODELS = [
    "dcim.site",
    "dcim.location",
    "dcim.rack",
    "dcim.device",
    "dcim.interface",
    "dcim.virtualdevicecontext",
    "ipam.ipaddress",
    "ipam.prefix",
    "ipam.aggregate",
    "ipam.vlan",
    "ipam.vrf",
    "virtualization.virtualmachine",
    "virtualization.vminterface",
    "virtualization.cluster",
    "circuits.circuit",
    "circuits.circuittermination",
    "tenancy.tenant",
    "vpn.tunnel",
    "wireless.wirelesslan",
]


class ServiceAssignmentsExtension(PluginTemplateExtension):
    models = [
        "netbox_certificates.artifactgroup",
        "netbox_certificates.bundle",
        "netbox_certificates.certificate",
        "netbox_certificates.privatekey",
        "netbox_certificates.csr",
    ]

    def right_page(self):
        obj = self.context.get("object")
        services = getattr(obj, "services", None)
        if services is None:
            return ""
        return self.render(
            "netbox_certificates/inc/service_assignments.html",
            extra_context={"linked_services": services.all().order_by("name")},
        )


class ObjectLinksExtension(PluginTemplateExtension):
    models = PLUGIN_RELATIONSHIP_MODELS + NATIVE_LINK_MODELS

    def right_page(self):
        obj = self.context.get("object")
        if obj is None or not getattr(obj, "pk", None):
            return ""
        content_type = ContentType.objects.get_for_model(obj, for_concrete_model=False)
        links = ObjectLink.objects.filter(
            source_type=content_type,
            source_object_id=obj.pk,
            enabled=True,
        ).select_related("target_type")
        reverse_links = ObjectLink.objects.filter(
            target_type=content_type,
            target_object_id=obj.pk,
            enabled=True,
        ).select_related("source_type")
        return self.render(
            "netbox_certificates/inc/object_links.html",
            extra_context={
                "object_links": links,
                "reverse_object_links": reverse_links,
                "source_content_type": content_type,
            },
        )


template_extensions = [ServiceAssignmentsExtension, ObjectLinksExtension]
