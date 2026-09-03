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
                    link="plugins:netbox_certificates:certificateauthority_list",
                    link_text="Certificate Authorities",
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:vault",
                    link_text="Cryptographic Vault",
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:health",
                    link_text="Health and Validity",
                ),
            ),
        ),
        (
            "Inventory",
            (
                PluginMenuItem(
                    link="plugins:netbox_certificates:artifactgroup_list",
                    link_text="Groups",
                    permissions=["netbox_certificates.view_artifactgroup"],
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:service_list",
                    link_text="Services",
                    permissions=["netbox_certificates.view_service"],
                ),
                PluginMenuItem(
                    link="plugins:netbox_certificates:bundle_list",
                    link_text="Bundles",
                ),
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
                    link="plugins:netbox_certificates:alertrule_list",
                    link_text="Alerts Configuration",
                    permissions=["netbox_certificates.view_alertrule"],
                ),
            ),
        ),
    ),
)
