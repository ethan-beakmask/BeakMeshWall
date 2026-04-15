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
