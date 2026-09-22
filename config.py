import os
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
if os.environ.get("VERCEL"):
    LOCAL_DATABASE_PATH = Path("/tmp/dev.db")
else:
    LOCAL_DATABASE_PATH = PROJECT_ROOT / "instance" / "dev.db"


class Config:
    """All configuration comes from environment variables so the same code
    runs locally, on Vercel, or on any other host. Copy .env.example to .env
    for local development.
    """

    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-only-secret-change-me")

    # SQLAlchemy: defaults to a local SQLite file for development.
    # On Vercel the filesystem is ephemeral and read-only outside /tmp, so for
    # any real deployment set DATABASE_URL to a hosted Postgres instance
    # (Vercel Postgres, Neon, Supabase all work) or scan history will not
    # persist between requests.
    _raw_db_url = os.environ.get("DATABASE_URL", f"sqlite:///{LOCAL_DATABASE_PATH.as_posix()}")
    if _raw_db_url.startswith("postgres://"):
        # SQLAlchemy 1.4+/2.x requires the "postgresql://" scheme; most
        # managed Postgres providers still hand out "postgres://" URLs.
        _raw_db_url = _raw_db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _raw_db_url
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Optional bonus features - each degrades gracefully if unset.
    ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL = os.environ.get("ANTHROPIC_MODEL", "claude-sonnet-5")

    CRON_SECRET = os.environ.get("CRON_SECRET")

    SMTP_HOST = os.environ.get("SMTP_HOST")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USER = os.environ.get("SMTP_USER")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
    MAIL_FROM = os.environ.get("MAIL_FROM", "scanner@example.com")

    # Safety limits for the scan engine - keep these modest so a scan finishes
    # comfortably inside a serverless function's execution window and never
    # turns into a de-facto denial-of-service against the target.
    HTTP_TIMEOUT_SECONDS = float(os.environ.get("HTTP_TIMEOUT_SECONDS", "8"))
    PORT_SCAN_TIMEOUT_SECONDS = float(os.environ.get("PORT_SCAN_TIMEOUT_SECONDS", "0.75"))
    PORT_SCAN_MAX_WORKERS = int(os.environ.get("PORT_SCAN_MAX_WORKERS", "12"))
    MAX_TIMING_PROBE_DELAY = float(os.environ.get("MAX_TIMING_PROBE_DELAY", "3"))
