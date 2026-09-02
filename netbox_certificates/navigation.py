from netbox.plugins import PluginMenu, PluginMenuItem


menu = PluginMenu(
    label="SSL Certificates",
    icon_class="mdi mdi-certificate-outline",
    groups=(
        (
            "Overview",
            (
                PluginMenuItem(
                    link="plugins:netbox_certificates:expiration_dashboard",
                    link_text="Expiration Dashboard",
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:inventory",
                    link_text="Inventory",
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:certificateauthority_list",
                    link_text="Certificate Authorities",
                    permissions=["netbox_certificates.view_certificateauthority"],
                ),
            ),
        ),
        (
            "Inventory",
            (
                PluginMenuItem(
                    link="plugins:netbox_certificates:certificate_list",
                    link_text="Certificates",
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:privatekey_list",
                    link_text="Private Keys",
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:csr_list",
                    link_text="CSRs",
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:bundle_list",
                    link_text="Bundles",
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:artifactgroup_list",
                    link_text="Groups",
                    permissions=["netbox_certificates.view_artifactgroup"],
                ),
            ),
        ),
        (
            "Operations",
            (
                PluginMenuItem(
                    link="plugins:netbox_certificates:import_objects",
                    link_text="Import Objects",
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:csr_generate",
                    link_text="Generate CSR",
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:expiration_alerts",
                    link_text="Expiration Alerts",
                ),
            ),
        ),
    ),
)
