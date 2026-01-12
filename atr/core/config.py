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
    
    # Transparency log settings (v0.3)
    transparency_log_enabled: bool = True
    
    # Domain validation settings (v0.3)
    domain_validation_enabled: bool = False
    
    # Async processing settings (v0.3)
    async_processing_enabled: bool = False  # For now, disabled by default
    
    # v0.4: Hybrid Certificate Architecture - ACME/Let's Encrypt settings
    acme_enabled: bool = False  # Enable public certificate issuance via ACME
    acme_account_email: Optional[str] = None  # Email for ACME account registration
    acme_directory_url: str = "https://acme-staging-v02.api.letsencrypt.org/directory"  # Staging by default
    acme_use_staging: bool = True  # Use staging environment (recommended for testing)
    
    # OCSP settings (v0.4)
    ocsp_enabled: bool = True
    
    # v0.4: Phase 5 - RA Orchestration settings
    ra_workflow_enabled: bool = True  # Enable workflow engine
    ra_policy_enabled: bool = True  # Enable policy engine
    certificate_renewal_enabled: bool = False  # Enable automated certificate renewal
    certificate_renewal_days_ahead: int = 7  # Days before expiry to renew
    certificate_renewal_check_interval: int = 3600  # Check interval in seconds (default: 1 hour)
    
    # v0.4: Phase 7 - Security Enhancements settings
    hsm_enabled: bool = False  # Enable HSM integration
    hsm_type: str = "file"  # HSM type: file, aws, azure
    hsm_key_dir: Optional[Path] = None  # Directory for file-based HSM (defaults to pki_root_dir/hsm)
    aws_hsm_cluster_id: Optional[str] = None  # AWS CloudHSM cluster ID
    aws_hsm_key_arn: Optional[str] = None  # AWS CloudHSM key ARN
    azure_key_vault_url: Optional[str] = None  # Azure Key Vault URL
    
    # Advanced rate limiting (per-domain)
    rate_limit_per_domain_enabled: bool = False  # Enable per-domain rate limiting
    rate_limit_per_domain_per_minute: int = 10  # Requests per minute per domain
    
    # Security monitoring
    security_monitoring_enabled: bool = False  # Enable security monitoring
    anomaly_detection_enabled: bool = False  # Enable anomaly detection
    
    # v0.4: Phase 6 - Performance Monitoring settings
    performance_monitoring_enabled: bool = False  # Enable performance monitoring
    query_cache_enabled: bool = False  # Enable query result caching
    db_query_logging_enabled: bool = False  # Enable database query logging (for debugging)
    db_pool_size: int = 5  # Database connection pool size
    db_pool_max_overflow: int = 10  # Maximum overflow connections
    
    model_config = {
        "env_file": ".env",
        "case_sensitive": False
    }


settings = Settings()

# Ensure directories exist
settings.pki_root_dir.mkdir(parents=True, exist_ok=True)
settings.keys_root_dir.mkdir(parents=True, exist_ok=True)
