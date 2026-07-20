import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "sentinel-dev-secret-change-in-prod")
    DEBUG = True

    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'sentinel.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    LOG_FILE = os.path.join(BASE_DIR, "logs", "sentinel.json")
    LOG_MAX_BYTES = 10 * 1024 * 1024
    LOG_BACKUP_COUNT = 5

    RATE_LIMIT_MAX_REQUESTS = 20
    RATE_LIMIT_WINDOW_SECONDS = 60
    RATE_LIMIT_BLOCK_DURATION = 300

    ALERT_ON_SEVERITY = ["HIGH", "CRITICAL"]
    WAF_BLOCK_MODE = True

    DASHBOARD_PAGE_SIZE = 50
