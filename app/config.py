import os
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    API_KEY: str = "secure_shared_lab_key_2026"
    DATABASE_URL: str = "sqlite+aiosqlite:///./platform.db"
    RUNNER_API_BASE: str = "http://127.0.0.1:8001"
    MOCK_RUNNER: bool = True
    OPENAI_API_KEY: str = "mock-key"
    OPENAI_MODEL: str = "gpt-4o-mini"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
