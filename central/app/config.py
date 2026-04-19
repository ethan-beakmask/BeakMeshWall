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
