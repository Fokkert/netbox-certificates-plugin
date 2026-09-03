# Uninstall

The plugin stores encrypted private-key material and certificate-management relationships. Back up PostgreSQL and the Fernet key before removing it.

A safe disable sequence is:

1. stop any operational dependency on the plugin API;
2. remove `netbox_certificates` from `PLUGINS`;
3. remove/pin changes in `local_requirements.txt`;
4. run the normal NetBox upgrade;
5. restart NetBox.

Disabling/uninstalling the Python package does not automatically drop plugin database tables.

Do not delete plugin tables without a verified backup and a confirmed data-removal plan.

If the intent is a rollback from a failed 1.0 upgrade, restore the pre-upgrade database backup instead of trying to manually delete only the new 1.0 tables.
