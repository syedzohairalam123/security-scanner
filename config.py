"""Application configuration, read entirely from environment variables.

Everything in this module is evaluated while ``app`` is being imported, which
on Vercel happens inside the generated function bootstrap. An unhandled
exception here is reported only as ``could not import 'app.py'`` with a bare
traceback, so parsing is deliberately defensive: an *optional* value that is
blank or malformed falls back to its default and says so on stderr instead of
taking the whole deployment down at import time.
"""

import os
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent

# Vercel sets VERCEL=1 in both the build and the function runtime.
ON_VERCEL = bool(os.environ.get("VERCEL"))

if ON_VERCEL:
    # Vercel's filesystem is read-only apart from /tmp, and /tmp is per
    # instance. See README.md - a hosted Postgres (DATABASE_URL) is what makes
    # scan history persist across requests and instances.
    LOCAL_DATABASE_PATH = Path("/tmp/dev.db")
else:
    LOCAL_DATABASE_PATH = PROJECT_ROOT / "instance" / "dev.db"

LOCAL_DATABASE_URL = f"sqlite:///{LOCAL_DATABASE_PATH.as_posix()}"


def _warn(message: str) -> None:
    """stderr survives Vercel's log capture even when logging is not configured."""
    print(f"[config] {message}", file=sys.stderr)


def _env(name: str, default=None):
    """Environment lookup where blank (or whitespace) counts as unset.

    ``os.environ.get(name, default)`` returns an empty string - not the
    default - when a variable is set but empty, which is exactly what happens
    when an env var is pasted from ``.env.example`` with no value, or left
    blank in a hosting dashboard. A blank numeric value used to reach
    ``int("")`` and crash the import, so blanks are normalised here.
    """
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    return raw.strip()


def _env_number(name: str, default: int | float, cast):
    """Numeric env var that can never raise: bad values fall back to default."""
    raw = _env(name)
    if raw is None:
        return default
    try:
        return cast(raw)
    except (TypeError, ValueError):
        _warn(f"{name}={raw!r} is not a valid number; using {default!r} instead")
        return default


def _sqlite_url_is_relative(url: str) -> bool:
    """True for ``sqlite:///relative.db`` style URLs.

    SQLAlchemy reads three slashes as a *relative* file path and four as an
    absolute one, so ``sqlite:///dev.db`` (the value in .env.example) means
    "dev.db next to the current working directory", while
    ``sqlite:////tmp/dev.db`` is the absolute /tmp/dev.db. An in-memory
    database has nothing to rewrite.
    """
    if not url.startswith("sqlite"):
        return False
    _, _, remainder = url.partition("://")
    if not remainder or ":memory:" in remainder:
        return False
    return not remainder.startswith("//")


def _database_url() -> str:
    """Resolve SQLALCHEMY_DATABASE_URI from DATABASE_URL.

    Two footguns are handled here because both produce a deployment that boots
    and then fails on every page:

    * ``postgres://`` - most managed providers still hand this scheme out, but
      SQLAlchemy 1.4+/2.x requires ``postgresql://``.
    * a *relative* SQLite path on Vercel - the working directory is read-only
      there, so the tables can never be created and every query raises
      "no such table". Point it at the one writable directory instead.
    """
    raw = _env("DATABASE_URL")
    if raw is None:
        return LOCAL_DATABASE_URL

    if raw.startswith("postgres://"):
        raw = raw.replace("postgres://", "postgresql://", 1)

    if ON_VERCEL and _sqlite_url_is_relative(raw):
        _warn(
            f"DATABASE_URL={raw!r} is a relative SQLite path, which cannot be "
            f"written on Vercel; using {LOCAL_DATABASE_URL!r} instead. Set "
            "DATABASE_URL to a hosted Postgres URL so data persists."
        )
        return LOCAL_DATABASE_URL

    return raw


def _engine_options(uri: str) -> dict:
    """SQLAlchemy engine options, bounded so boot cannot hang forever.

    Schema creation runs during function initialisation, and a cold start has
    a hard time limit - so an unreachable database host must fail fast (it is
    caught and logged in app._prepare_database) instead of blocking the boot
    until the platform kills the function.
    """
    options = {"pool_pre_ping": True}
    if uri.startswith("postgresql"):
        options["connect_args"] = {"connect_timeout": 5}
    return options


def _secret_key() -> str:
    value = _env("SECRET_KEY")
    if value:
        return value
    if ON_VERCEL:
        _warn(
            "SECRET_KEY is not set. Falling back to the development key, so "
            "sessions are not safe - set SECRET_KEY in the hosting dashboard."
        )
    return "dev-only-secret-change-me"


class Config:
    """All configuration comes from environment variables so the same code
    runs locally, on Vercel, or on any other host. Copy .env.example to .env
    for local development.
    """

    SECRET_KEY = _secret_key()

    # SQLAlchemy: defaults to a local SQLite file for development. On Vercel,
    # set DATABASE_URL to a hosted Postgres instance (Vercel Postgres, Neon,
    # Supabase all work) or scan history will not persist between requests.
    SQLALCHEMY_DATABASE_URI = _database_url()
    SQLALCHEMY_ENGINE_OPTIONS = _engine_options(SQLALCHEMY_DATABASE_URI)
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Optional bonus features - each degrades gracefully if unset.
    ANTHROPIC_API_KEY = _env("ANTHROPIC_API_KEY")
    ANTHROPIC_MODEL = _env("ANTHROPIC_MODEL", "claude-sonnet-5")

    CRON_SECRET = _env("CRON_SECRET")

    SMTP_HOST = _env("SMTP_HOST")
    SMTP_PORT = _env_number("SMTP_PORT", 587, int)
    SMTP_USER = _env("SMTP_USER")
    SMTP_PASSWORD = _env("SMTP_PASSWORD")
    MAIL_FROM = _env("MAIL_FROM", "scanner@example.com")

    # Safety limits for the scan engine - keep these modest so a scan finishes
    # comfortably inside a serverless function's execution window and never
    # turns into a de-facto denial-of-service against the target.
    HTTP_TIMEOUT_SECONDS = _env_number("HTTP_TIMEOUT_SECONDS", 8.0, float)
    PORT_SCAN_TIMEOUT_SECONDS = _env_number("PORT_SCAN_TIMEOUT_SECONDS", 0.75, float)
    PORT_SCAN_MAX_WORKERS = _env_number("PORT_SCAN_MAX_WORKERS", 12, int)
    MAX_TIMING_PROBE_DELAY = _env_number("MAX_TIMING_PROBE_DELAY", 3.0, float)
