from datetime import datetime, timezone


def utcnow() -> datetime:
    """Naive UTC datetime (matches what every DateTime column in this app
    already stores) without using the deprecated datetime.utcnow()."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
