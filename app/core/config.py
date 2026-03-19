from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = Field(default="SentinelFlow API", alias="APP_NAME")
    app_env: str = Field(default="development", alias="APP_ENV")
    app_debug: bool = Field(default=True, alias="APP_DEBUG")

    database_url: str = Field(
        default="postgresql+asyncpg://sentinelflow:sentinelflow@localhost:5432/sentinelflow",
        alias="DATABASE_URL",
    )

    frontend_origin: str = Field(default="http://localhost:3000", alias="FRONTEND_ORIGIN")


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
