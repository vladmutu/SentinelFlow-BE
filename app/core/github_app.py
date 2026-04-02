from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import settings


def get_app_jwt() -> str:
    if settings.github_app_id <= 0 or not settings.github_app_private_key:
        raise ValueError("GitHub App credentials are not configured")

    now = datetime.now(timezone.utc)
    # Backdate iat to tolerate minor clock skew between local host and GitHub.
    issued_at = now - timedelta(seconds=60)
    payload = {
        "iat": int(issued_at.timestamp()),
        "exp": int((issued_at + timedelta(minutes=10)).timestamp()),
        "iss": str(settings.github_app_id),
    }

    private_key = settings.github_app_private_key.replace("\\n", "\n")
    return jwt.encode(payload, private_key, algorithm="RS256")
