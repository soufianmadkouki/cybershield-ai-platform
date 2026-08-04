from enum import StrEnum


class AssetType(StrEnum):
    SERVER = "server"
    WORKSTATION = "workstation"
    LAPTOP = "laptop"
    VIRTUAL_MACHINE = "virtual_machine"
    CONTAINER = "container"
    KUBERNETES_NODE = "kubernetes_node"
    NETWORK_DEVICE = "network_device"
    FIREWALL = "firewall"
    ROUTER = "router"
    SWITCH = "switch"
    CLOUD_INSTANCE = "cloud_instance"
    DATABASE = "database"
    STORAGE = "storage"
    DOMAIN = "domain"
    WEBSITE = "website"
    APPLICATION = "application"
    OTHER = "other"


class AssetEnvironment(StrEnum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    TEST = "test"
    SANDBOX = "sandbox"
    UNKNOWN = "unknown"


class AssetCriticality(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class AssetStatus(StrEnum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    DECOMMISSIONED = "decommissioned"
    UNKNOWN = "unknown"


class AssetDiscoverySource(StrEnum):
    MANUAL = "manual"
    API = "api"
    AGENT = "agent"
    NETWORK_SCAN = "network_scan"
    CLOUD_CONNECTOR = "cloud_connector"
    IMPORT = "import"
    OTHER = "other"
