from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Sensitive Data Detection API"
    app_version: str = "1.0.0"
    debug: bool = False

    database_url: str = "sqlite:///./data/sensitive_data.db"
    database_pool_size: int = 10
    database_max_overflow: int = 20

    api_key_header: str = "X-API-Key"
    api_keys: dict = {"default": "test-api-key"}

    rules_file: str = "app/rules/rules.yaml"
    rules_hot_reload: bool = True
    rules_reload_interval: int = 30

    default_tenant: str = "default"

    batch_max_size_mb: int = 10
    batch_worker_interval: float = 1.0

    hash_salt: str = "sensitive-data-salt"

    ner_enabled: bool = False
    ner_model_path: str | None = None

    ip_private_ranges: list = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
    ]


settings = Settings()
