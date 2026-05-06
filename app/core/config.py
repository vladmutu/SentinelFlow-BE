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
    static_analysis_remote_url: str = Field(
        default="http://localhost:8090",
        alias="STATIC_ANALYSIS_REMOTE_URL",
    )
    scanner_model_path: str = Field(default="malware_classifier.pkl", alias="SCANNER_MODEL_PATH")
    scanner_threshold_path: str = Field(default="malware_threshold.pkl", alias="SCANNER_THRESHOLD_PATH")
    scanner_artifact_max_files: int = Field(default=50000, alias="SCANNER_ARTIFACT_MAX_FILES")
    scanner_artifact_max_total_bytes: int = Field(default=500000000, alias="SCANNER_ARTIFACT_MAX_TOTAL_BYTES")
    scanner_artifact_extract_timeout_seconds: int = Field(
        default=30,
        alias="SCANNER_ARTIFACT_EXTRACT_TIMEOUT_SECONDS",
    )
    scan_result_reuse_enabled: bool = Field(default=True, alias="SCAN_RESULT_REUSE_ENABLED")
    scan_result_reuse_ttl_seconds: int = Field(default=3600, alias="SCAN_RESULT_REUSE_TTL_SECONDS")

    # Dependency PR workflow settings
    npm_lockfile_generation_enabled: bool = Field(
        default=True,
        alias="NPM_LOCKFILE_GENERATION_ENABLED",
    )
    npm_lockfile_generation_timeout_seconds: int = Field(
        default=120,
        alias="NPM_LOCKFILE_GENERATION_TIMEOUT_SECONDS",
    )

    librariesio_api_key: str = Field(
        default="",
        alias="LIBRARIESIO_API_KEY",
    )

    # Vulnerability intelligence settings
    vulnerability_lookup_enabled: bool = Field(
        default=True,
        alias="VULNERABILITY_LOOKUP_ENABLED",
    )
    osv_api_url: str = Field(
        default="https://api.osv.dev/v1/query",
        alias="OSV_API_URL",
    )
    nvd_api_url: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        alias="NVD_API_URL",
    )
    nvd_api_key: str = Field(
        default="",
        alias="NVD_API_KEY",
    )
    vulnerability_lookup_timeout_seconds: int = Field(
        default=8,
        alias="VULNERABILITY_LOOKUP_TIMEOUT_SECONDS",
    )
    vulnerability_cache_ttl_seconds: int = Field(
        default=900,
        alias="VULNERABILITY_CACHE_TTL_SECONDS",
    )
    vulnerability_max_nvd_results: int = Field(
        default=20,
        alias="VULNERABILITY_MAX_NVD_RESULTS",
    )

    # False-positive policy controls
    risk_policy_allowlist: str = Field(
        default="",
        alias="RISK_POLICY_ALLOWLIST",
    )
    risk_policy_min_confidence: float = Field(
        default=0.35,
        alias="RISK_POLICY_MIN_CONFIDENCE",
    )
    risk_policy_suppress_on_low_confidence: bool = Field(
        default=True,
        alias="RISK_POLICY_SUPPRESS_ON_LOW_CONFIDENCE",
    )
    risk_policy_suppressed_score_ceiling: float = Field(
        default=0.2,
        alias="RISK_POLICY_SUPPRESSED_SCORE_CEILING",
    )
    risk_policy_static_weight_scale: float = Field(
        default=1.0,
        alias="RISK_POLICY_STATIC_WEIGHT_SCALE",
    )
    risk_policy_vulnerability_weight_scale: float = Field(
        default=1.0,
        alias="RISK_POLICY_VULNERABILITY_WEIGHT_SCALE",
    )
    risk_policy_reputation_weight_scale: float = Field(
        default=1.0,
        alias="RISK_POLICY_REPUTATION_WEIGHT_SCALE",
    )

    # Unified risk scoring controls
    risk_scoring_classifier_weight: float = Field(
        default=0.5,
        alias="RISK_SCORING_CLASSIFIER_WEIGHT",
    )
    risk_scoring_static_weight: float = Field(
        default=0.2,
        alias="RISK_SCORING_STATIC_WEIGHT",
    )
    risk_scoring_vulnerability_weight: float = Field(
        default=0.25,
        alias="RISK_SCORING_VULNERABILITY_WEIGHT",
    )
    risk_scoring_reputation_weight: float = Field(
        default=0.05,
        alias="RISK_SCORING_REPUTATION_WEIGHT",
    )
    risk_scoring_dynamic_weight: float = Field(
        default=0.0,
        alias="RISK_SCORING_DYNAMIC_WEIGHT",
    )
    risk_scoring_clean_max: float = Field(
        default=0.34,
        alias="RISK_SCORING_CLEAN_MAX",
    )
    risk_scoring_suspicious_max: float = Field(
        default=0.69,
        alias="RISK_SCORING_SUSPICIOUS_MAX",
    )

    # Dynamic-analysis boundary controls (remote sandbox only)
    dynamic_analysis_enabled: bool = Field(
        default=False,
        alias="DYNAMIC_ANALYSIS_ENABLED",
    )
    dynamic_analysis_mode: str = Field(
        default="remote",
        alias="DYNAMIC_ANALYSIS_MODE",
    )
    dynamic_analysis_remote_url: str = Field(
        default="http://localhost:8080",
        alias="DYNAMIC_ANALYSIS_REMOTE_URL",
    )
    dynamic_analysis_api_key: str = Field(
        default="",
        alias="DYNAMIC_ANALYSIS_API_KEY",
    )
    dynamic_analysis_timeout_seconds: int = Field(
        default=15,
        alias="DYNAMIC_ANALYSIS_TIMEOUT_SECONDS",
    )
    dynamic_analysis_fail_open: bool = Field(
        default=True,
        alias="DYNAMIC_ANALYSIS_FAIL_OPEN",
    )
    dynamic_analysis_send_artifact_metadata: bool = Field(
        default=True,
        alias="DYNAMIC_ANALYSIS_SEND_ARTIFACT_METADATA",
    )
    dynamic_analysis_concurrency: int = Field(
        default=4,
        alias="DYNAMIC_ANALYSIS_CONCURRENCY",
    )
    dynamic_analysis_cache_ttl_seconds: int = Field(
        default=1800,
        alias="DYNAMIC_ANALYSIS_CACHE_TTL_SECONDS",
    )
    dynamic_analysis_priority_threshold: float = Field(
        default=0.55,
        alias="DYNAMIC_ANALYSIS_PRIORITY_THRESHOLD",
    )
    dynamic_analysis_force_on_vulnerability: bool = Field(
        default=True,
        alias="DYNAMIC_ANALYSIS_FORCE_ON_VULNERABILITY",
    )
    dynamic_analysis_sandbox_type: str = Field(
        default="generic",
        alias="DYNAMIC_ANALYSIS_SANDBOX_TYPE",
    )
    firecracker_kernel_path: str = Field(
        default="",
        alias="FIRECRACKER_KERNEL_PATH",
    )
    firecracker_rootfs_path: str = Field(
        default="",
        alias="FIRECRACKER_ROOTFS_PATH",
    )

    # GitHub Webhook settings
    github_webhook_secret: str = Field(
        default="placeholder-webhook-secret-change-me",
        alias="GITHUB_WEBHOOK_SECRET",
    )
    webhook_auto_scan_enabled: bool = Field(
        default=True,
        alias="WEBHOOK_AUTO_SCAN_ENABLED",
    )
    webhook_auto_scan_ecosystems: str = Field(
        default="npm,pypi",
        alias="WEBHOOK_AUTO_SCAN_ECOSYSTEMS",
    )
    webhook_ngrok_enabled: bool = Field(
        default=False,
        alias="WEBHOOK_NGROK_ENABLED",
    )
    webhook_ngrok_authtoken: str = Field(
        default="",
        alias="WEBHOOK_NGROK_AUTHTOKEN",
    )
    webhook_ngrok_domain: str = Field(
        default="",
        alias="WEBHOOK_NGROK_DOMAIN",
    )

    # Typosquat guard settings
    typosquat_check_enabled: bool = Field(
        default=True,
        alias="TYPOSQUAT_CHECK_ENABLED",
    )
    typosquat_block_threshold: float = Field(
        default=0.85,
        alias="TYPOSQUAT_BLOCK_THRESHOLD",
    )

    # Reputation service settings
    reputation_lookup_enabled: bool = Field(
        default=True,
        alias="REPUTATION_LOOKUP_ENABLED",
    )
    reputation_lookup_timeout_seconds: int = Field(
        default=8,
        alias="REPUTATION_LOOKUP_TIMEOUT_SECONDS",
    )
    reputation_cache_ttl_seconds: int = Field(
        default=3600,
        alias="REPUTATION_CACHE_TTL_SECONDS",
    )

    # SBOM settings
    sbom_license_fetch_enabled: bool = Field(
        default=True,
        alias="SBOM_LICENSE_FETCH_ENABLED",
    )
    sbom_license_fetch_concurrency: int = Field(
        default=10,
        alias="SBOM_LICENSE_FETCH_CONCURRENCY",
    )

@lru_cache
def get_settings() -> Settings:
    """Return cached application settings loaded from environment variables.

    Returns:
        Settings: Singleton configuration object.
    """
    return Settings()


settings = get_settings()
