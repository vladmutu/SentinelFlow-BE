from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = Field(default="SentinelFlow API", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")
    api_v1_prefix: str = Field(default="/api", alias="API_V1_PREFIX")

    database_url: str = Field(
        default="postgresql+asyncpg://sentinel_admin:supersecretpassword@localhost:5433/sentinel_core",
        alias="DATABASE_URL",
    )

    cors_allow_origins: list[str] = Field(
        default=["http://localhost:3000"],
        alias="CORS_ALLOW_ORIGINS",
    )

    frontend_url: str = Field(default="http://localhost:3000", alias="FRONTEND_URL")

    github_client_id: str = Field(default="", alias="GITHUB_CLIENT_ID")
    github_client_secret: str = Field(default="", alias="GITHUB_CLIENT_SECRET")
    github_redirect_uri: str = Field(
        default="http://localhost:8000/api/auth/github/callback",
        alias="GITHUB_REDIRECT_URI",
    )

    github_app_id: int = Field(alias="GITHUB_APP_ID")
    github_app_private_key: str = Field(alias="GITHUB_APP_PRIVATE_KEY")

    jwt_secret_key: str = Field(default="change-me-in-env", alias="JWT_SECRET_KEY")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    jwt_expire_minutes: int = Field(default=60, alias="JWT_EXPIRE_MINUTES")

    # Scanner / malware-classification settings
    scanner_concurrency: int = Field(default=10, alias="SCANNER_CONCURRENCY")
    scanner_model_path: str = Field(default="malware_classifier.pkl", alias="SCANNER_MODEL_PATH")
    scanner_threshold_path: str = Field(default="malware_threshold.pkl", alias="SCANNER_THRESHOLD_PATH")


@lru_cache
def get_settings() -> Settings:
    """Return cached application settings loaded from environment variables.

    Returns:
        Settings: Singleton configuration object.
    """
    return Settings()


settings = get_settings()
