from datetime import datetime, timedelta, timezone

from jose import JWTError, jwt
 
from app.core.config import settings


def create_access_token(subject: str) -> str:
    """Create a signed JWT access token for a user subject.

    Args:
        subject: User identifier to store in the ``sub`` claim.

    Returns:
        str: Encoded JWT string.
    """
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload = {
        "sub": subject,
        "exp": expires_at,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict:
    """Decode and validate an access token.

    Args:
        token: Encoded JWT string.

    Returns:
        dict: Decoded JWT payload claims.

    Raises:
        ValueError: If the token cannot be decoded or validated.
    """
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise ValueError("Invalid access token") from exc
