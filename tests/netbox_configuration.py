"""Disposable NetBox CI configuration; never use these credentials in production."""
from netbox.configuration_testing import *  # noqa: F403

PLUGINS = ["netbox_certificates"]
PLUGINS_CONFIG = {
    "netbox_certificates": {
        "encryption_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    },
}
