MAX_UPLOAD_BYTES = 25 * 1024 * 1024
MAX_ARCHIVE_FILES = 250
MAX_ARCHIVE_UNCOMPRESSED_BYTES = 100 * 1024 * 1024
ALLOW_RAR = True

EXPIRY_WARNING_DAYS = 30
EXPIRY_CRITICAL_DAYS = 7

ALERT_SYSTEM_JOB_INTERVAL_MINUTES = 1
DEFAULT_ALERT_CHECK_INTERVAL_MINUTES = 60
ALERT_CHECK_INTERVAL_CHOICES = (
    (5, "Every 5 minutes"),
    (10, "Every 10 minutes"),
    (15, "Every 15 minutes"),
    (30, "Every 30 minutes"),
    (60, "Every hour"),
    (180, "Every 3 hours"),
    (360, "Every 6 hours"),
    (720, "Every 12 hours"),
    (1440, "Every 24 hours"),
)
