from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AUDITOR_", env_file=".env")

    max_response_bytes: int = 1_048_576
    request_timeout_seconds: float = 10.0
    scan_deadline_seconds: float = 30.0
    max_redirects: int = 5
    database_path: str = "evidence_auditor.sqlite3"
    deep_scan_max_assets: int = 10
    deep_scan_max_asset_bytes: int = 262_144


settings = Settings()
