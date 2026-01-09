"""Configuration management"""
from pathlib import Path
from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings"""
    
    database_url: str = "sqlite:///./atr.db"
    pki_root_dir: Path = Path("./var/pki")
    keys_root_dir: Path = Path("./var/keys")
    host: str = "0.0.0.0"
    port: int = 8000
    
    # CA settings
    ca_validity_days: int = 3650  # 10 years for root/intermediate
    cert_validity_days: int = 30  # 30 days for leaf certs
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": False
    }


settings = Settings()

# Ensure directories exist
settings.pki_root_dir.mkdir(parents=True, exist_ok=True)
settings.keys_root_dir.mkdir(parents=True, exist_ok=True)
