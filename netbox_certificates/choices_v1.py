from utilities.choices import ChoiceSet


class ServiceStatusChoices(ChoiceSet):
    key = "netbox_certificates.Service.status"

    ACTIVE = "active"
    PLANNED = "planned"
    MAINTENANCE = "maintenance"
    DEPRECATED = "deprecated"
    OFFLINE = "offline"

    CHOICES = [
        (ACTIVE, "Active", "green"),
        (PLANNED, "Planned", "blue"),
        (MAINTENANCE, "Maintenance", "orange"),
        (DEPRECATED, "Deprecated", "yellow"),
        (OFFLINE, "Offline", "gray"),
    ]


class ServiceTypeChoices(ChoiceSet):
    key = "netbox_certificates.Service.service_type"

    WEB_SERVER = "web_server"
    WEBSITE = "website"
    REPOSITORY = "repository"
    CONTAINER_REGISTRY = "container_registry"
    API = "api"
    API_GATEWAY = "api_gateway"
    REVERSE_PROXY = "reverse_proxy"
    LOAD_BALANCER = "load_balancer"
    KUBERNETES = "kubernetes"
    OPENSHIFT = "openshift"
    CI_CD = "ci_cd"
    GIT_SERVICE = "git_service"
    ARTIFACT_REPOSITORY = "artifact_repository"
    MAIL_SERVER = "mail_server"
    DATABASE = "database"
    DIRECTORY = "directory"
    VPN = "vpn"
    REMOTE_ACCESS = "remote_access"
    MONITORING = "monitoring"
    MESSAGE_BROKER = "message_broker"
    STORAGE = "storage"
    IDENTITY = "identity"
    INTERNAL_APPLICATION = "internal_application"
    EXTERNAL_APPLICATION = "external_application"
    OTHER = "other"

    CHOICES = [
        (WEB_SERVER, "Web Server", "blue"),
        (WEBSITE, "Website", "blue"),
        (REPOSITORY, "Repository", "purple"),
        (CONTAINER_REGISTRY, "Container Registry", "purple"),
        (API, "API", "cyan"),
        (API_GATEWAY, "API Gateway", "cyan"),
        (REVERSE_PROXY, "Reverse Proxy", "indigo"),
        (LOAD_BALANCER, "Load Balancer", "indigo"),
        (KUBERNETES, "Kubernetes", "blue"),
        (OPENSHIFT, "OpenShift", "red"),
        (CI_CD, "CI/CD", "teal"),
        (GIT_SERVICE, "Git Service", "purple"),
        (ARTIFACT_REPOSITORY, "Artifact Repository", "purple"),
        (MAIL_SERVER, "Mail Server", "yellow"),
        (DATABASE, "Database", "green"),
        (DIRECTORY, "Directory / LDAP", "orange"),
        (VPN, "VPN", "red"),
        (REMOTE_ACCESS, "Remote Access", "red"),
        (MONITORING, "Monitoring", "cyan"),
        (MESSAGE_BROKER, "Message Broker", "orange"),
        (STORAGE, "Storage", "green"),
        (IDENTITY, "Identity Service", "yellow"),
        (INTERNAL_APPLICATION, "Internal Application", "gray"),
        (EXTERNAL_APPLICATION, "External Application", "gray"),
        (OTHER, "Other", "gray"),
    ]


class ServiceEnvironmentChoices(ChoiceSet):
    key = "netbox_certificates.Service.environment"

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TESTING = "testing"
    LAB = "lab"
    OTHER = "other"

    CHOICES = [
        (PRODUCTION, "Production", "red"),
        (STAGING, "Staging", "orange"),
        (DEVELOPMENT, "Development", "blue"),
        (TESTING, "Testing", "cyan"),
        (LAB, "Lab", "purple"),
        (OTHER, "Other", "gray"),
    ]


class ServiceCriticalityChoices(ChoiceSet):
    key = "netbox_certificates.Service.criticality"

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    CHOICES = [
        (LOW, "Low", "gray"),
        (MEDIUM, "Medium", "yellow"),
        (HIGH, "High", "orange"),
        (CRITICAL, "Critical", "red"),
    ]


class FindingSeverityChoices(ChoiceSet):
    key = "netbox_certificates.HealthFinding.severity"

    INFO = "info"
    WARNING = "warning"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    CHOICES = [
        (INFO, "Info", "blue"),
        (WARNING, "Warning", "yellow"),
        (MEDIUM, "Medium", "orange"),
        (HIGH, "High", "red"),
        (CRITICAL, "Critical", "red"),
    ]


class FindingStatusChoices(ChoiceSet):
    key = "netbox_certificates.HealthFinding.status"

    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    IGNORED = "ignored"
    RESOLVED = "resolved"

    CHOICES = [
        (ACTIVE, "Active", "red"),
        (ACKNOWLEDGED, "Acknowledged", "yellow"),
        (IGNORED, "Ignored", "gray"),
        (RESOLVED, "Resolved", "green"),
    ]


class AlertChannelTypeChoices(ChoiceSet):
    key = "netbox_certificates.AlertChannel.channel_type"

    EMAIL = "email"
    WEBHOOK = "webhook"

    CHOICES = [
        (EMAIL, "Email", "blue"),
        (WEBHOOK, "Webhook", "purple"),
    ]


class AlertEventStatusChoices(ChoiceSet):
    key = "netbox_certificates.AlertEvent.status"

    DELIVERED = "delivered"
    FAILED = "failed"
    SKIPPED = "skipped"

    CHOICES = [
        (DELIVERED, "Delivered", "green"),
        (FAILED, "Failed", "red"),
        (SKIPPED, "Skipped", "gray"),
    ]
