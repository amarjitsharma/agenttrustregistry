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
    
    # Redis settings (v0.2 MVP)
    redis_url: str = "redis://localhost:6379/0"
    redis_enabled: bool = True
    
    # DNS provider settings (v0.2 MVP)
    dns_provider: str = "local"  # local, route53, cloudflare
    route53_hosted_zone_id: Optional[str] = None
    route53_aws_access_key_id: Optional[str] = None
    route53_aws_secret_access_key: Optional[str] = None
    route53_aws_region: str = "us-east-1"
    cloudflare_api_token: Optional[str] = None
    cloudflare_zone_id: Optional[str] = None
    
    # Rate limiting settings (v0.2 MVP)
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 60
    rate_limit_per_hour: int = 1000
    
    # API authentication settings (v0.2 MVP)
    api_key_enabled: bool = False  # Enable API key authentication
    api_key_header: str = "X-API-Key"
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": False
    }


settings = Settings()

# Ensure directories exist
settings.pki_root_dir.mkdir(parents=True, exist_ok=True)
settings.keys_root_dir.mkdir(parents=True, exist_ok=True)
