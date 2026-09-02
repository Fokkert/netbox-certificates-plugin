from utilities.choices import ChoiceSet


class CertificateStatusChoices(ChoiceSet):
    key = "Certificate.status"
    ACTIVE = "active"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    INVALID = "invalid"
    CHOICES = [
        (ACTIVE, "Active", "green"),
        (EXPIRED, "Expired", "red"),
        (NOT_YET_VALID, "Not yet valid", "yellow"),
        (INVALID, "Invalid", "gray"),
    ]


class SourceFormatChoices(ChoiceSet):
    key = "CryptoArtifact.source_format"
    PEM = "pem"
    DER = "der"
    PKCS12 = "pkcs12"
    PKCS7 = "pkcs7"
    UNKNOWN = "unknown"
    CHOICES = [
        (PEM, "PEM"),
        (DER, "DER"),
        (PKCS12, "PKCS#12 / PFX"),
        (PKCS7, "PKCS#7"),
        (UNKNOWN, "Unknown"),
    ]


class BundleFormatChoices(ChoiceSet):
    key = "Bundle.archive_format"
    MANUAL = "manual"
    ZIP = "zip"
    TAR = "tar"
    RAR = "rar"
    CHOICES = [
        (MANUAL, "Manual / no archive"),
        (ZIP, "ZIP"),
        (TAR, "TAR/TAR.GZ/TGZ/TBZ/TXZ"),
        (RAR, "RAR"),
    ]


class BundleStatusChoices(ChoiceSet):
    key = "Bundle.status"
    COMPLETE = "complete"
    PARTIAL = "partial"
    CHOICES = [
        (COMPLETE, "Complete", "green"),
        (PARTIAL, "Partial", "yellow"),
    ]


class LinkOriginChoices(ChoiceSet):
    key = "ArtifactLink.origin"
    AUTOMATIC = "automatic"
    MANUAL = "manual"
    BUNDLE = "bundle"
    PFX = "pfx"
    CHOICES = [
        (AUTOMATIC, "Automatic"),
        (MANUAL, "Manual"),
        (BUNDLE, "Bundle import"),
        (PFX, "PFX / PKCS#12 import"),
    ]


class LinkRelationChoices(ChoiceSet):
    key = "ArtifactLink.relation"
    KEY_MATCH = "key_match"
    CSR_MATCH = "csr_match"
    ISSUER = "issuer"
    BUNDLE_MEMBER = "bundle_member"
    ASSIGNED_TO = "assigned_to"
    RELATED = "related"
    CHOICES = [
        (KEY_MATCH, "Same cryptographic key"),
        (CSR_MATCH, "CSR/certificate match"),
        (ISSUER, "Issued by"),
        (BUNDLE_MEMBER, "Bundle member"),
        (ASSIGNED_TO, "Assigned to"),
        (RELATED, "Related"),
    ]


class AlertTriggerUnitChoices(ChoiceSet):
    key = "Certificate.trigger_unit"
    YEAR = "year"
    MONTH = "month"
    WEEK = "week"
    DAY = "day"
    HOUR = "hour"
    MINUTE = "minute"
    SECOND = "second"
    CHOICES = [
        (YEAR, "Year"),
        (MONTH, "Month"),
        (WEEK, "Week"),
        (DAY, "Day"),
        (HOUR, "Hour"),
        (MINUTE, "Minute"),
        (SECOND, "Second"),
    ]


class AlertMethodChoices(ChoiceSet):
    key = "ExpiryAlertEvent.method"
    EMAIL = "email"
    WEBHOOK = "webhook"
    CHOICES = [(EMAIL, "Email"), (WEBHOOK, "Webhook")]


class AlertRepeatModeChoices(ChoiceSet):
    key = "ExpiryAlertConfiguration.alert_repeat_mode"
    ONCE = "once"
    WHILE_DUE = "while_due"
    CHOICES = [
        (ONCE, "Send once per trigger"),
        (WHILE_DUE, "Send every check while due"),
    ]
