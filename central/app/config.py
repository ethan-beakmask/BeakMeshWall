import os


class Config:
    SECRET_KEY = os.environ.get("BMW_SECRET_KEY", "dev-secret-change-in-production")
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "BMW_DATABASE_URI",
        "postgresql://beakmeshwall:postgres123@127.0.0.1:5432/beakmeshwall",
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_size": 5}

    # Agent poll interval hint (seconds)
    AGENT_POLL_INTERVAL = int(os.environ.get("BMW_AGENT_POLL_INTERVAL", "5"))

    # Session lifetime (seconds)
    PERMANENT_SESSION_LIFETIME = int(
        os.environ.get("BMW_SESSION_LIFETIME", "3600")
    )

    # Unique cookie name to avoid collision with other Flask apps on the same domain
    SESSION_COOKIE_NAME = "bmw_session"

    # EDL (External Dynamic List) export directory
    # Hardware firewalls (Palo Alto, Fortinet, etc.) can fetch these plain-text files
    EDL_EXPORT_DIR = os.environ.get(
        "BMW_EDL_EXPORT_DIR",
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "edl_export"),
    )

    # Drift notification (P6 Stage D).
    # If BMW_SMTP_HOST is set, drift alerts are sent via SMTP to BMW_NOTIFY_TO.
    # Otherwise, alerts are appended to BMW_NOTIFY_LOG_PATH (stub mode).
    SMTP_HOST = os.environ.get("BMW_SMTP_HOST", "")
    SMTP_PORT = int(os.environ.get("BMW_SMTP_PORT", "25"))
    SMTP_FROM = os.environ.get("BMW_SMTP_FROM", "beakmeshwall@localhost")
    SMTP_USER = os.environ.get("BMW_SMTP_USER", "")
    SMTP_PASSWORD = os.environ.get("BMW_SMTP_PASSWORD", "")
    NOTIFY_TO = os.environ.get("BMW_NOTIFY_TO", "")
    NOTIFY_LOG_PATH = os.environ.get(
        "BMW_NOTIFY_LOG_PATH", "/opt/tmp/BeakMeshWall-dev-central-drift_notifications.log"
    )

    # Drift backup directory (used by overwrite policy before reconcile).
    DRIFT_BACKUP_DIR = os.environ.get(
        "BMW_DRIFT_BACKUP_DIR", "/opt/tmp/beakmeshwall-drift-backup"
    )
