"""Disposable NetBox CI configuration; never use these credentials in production."""
import os

from netbox.configuration_testing import *  # noqa: F403

PLUGINS = ["netbox_certificates"]
PLUGINS_CONFIG = {
    "netbox_certificates": {
        "encryption_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    },
}

if os.environ.get("NBCERT_TEST_DATABASE_TEMPLATE") == "netbox":
    # CI has already migrated this disposable database. Clone it into Django's
    # separate test database rather than applying NetBox's full graph twice.
    DATABASES["default"]["TEST"] = {"TEMPLATE": "netbox"}  # noqa: F405
