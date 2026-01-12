"""HSM (Hardware Security Module) Integration Framework (v0.4)

This module provides an abstraction layer for HSM integration, supporting
multiple HSM providers (AWS CloudHSM, Azure Key Vault, Google Cloud KMS, etc.)
while maintaining backward compatibility with file-based key storage.
"""
from typing import Optional, Protocol, Any
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding

from atr.core.config import settings


class HSMProvider(Protocol):
    """Protocol for HSM provider implementations"""
    
    def get_private_key(self, key_id: str) -> rsa.RSAPrivateKey:
        """Retrieve a private key from HSM"""
        ...
    
    def store_private_key(self, key_id: str, private_key: rsa.RSAPrivateKey) -> None:
        """Store a private key in HSM"""
        ...
    
    def sign_data(self, key_id: str, data: bytes) -> bytes:
        """Sign data using a key stored in HSM"""
        ...
    
    def delete_key(self, key_id: str) -> None:
        """Delete a key from HSM"""
        ...


class FileBasedHSM:
    """File-based HSM implementation (fallback for development)"""
    
    def __init__(self, key_dir: Path):
        self.key_dir = key_dir
        self.key_dir.mkdir(parents=True, exist_ok=True)
    
    def get_private_key(self, key_id: str) -> rsa.RSAPrivateKey:
        """Load private key from file"""
        key_path = self.key_dir / f"{key_id}.key"
        if not key_path.exists():
            raise ValueError(f"Key {key_id} not found")
        
        key_data = key_path.read_bytes()
        return serialization.load_pem_private_key(key_data, password=None)
    
    def store_private_key(self, key_id: str, private_key: rsa.RSAPrivateKey) -> None:
        """Store private key to file"""
        key_path = self.key_dir / f"{key_id}.key"
        key_data = private_key.private_bytes(
            Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        key_path.write_bytes(key_data)
        # Set restrictive permissions
        key_path.chmod(0o600)
    
    def sign_data(self, key_id: str, data: bytes) -> bytes:
        """Sign data using file-based key"""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        
        private_key = self.get_private_key(key_id)
        return private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    
    def delete_key(self, key_id: str) -> None:
        """Delete key file"""
        key_path = self.key_dir / f"{key_id}.key"
        if key_path.exists():
            key_path.unlink()


class AWSCloudHSM:
    """AWS CloudHSM integration (placeholder for production)"""
    
    def __init__(self, cluster_id: Optional[str] = None, key_arn: Optional[str] = None):
        self.cluster_id = cluster_id
        self.key_arn = key_arn
        # In production, initialize boto3 CloudHSM client
        # self.client = boto3.client('cloudhsmv2')
    
    def get_private_key(self, key_id: str) -> rsa.RSAPrivateKey:
        """Retrieve private key from AWS CloudHSM"""
        # Placeholder - in production, use boto3 to retrieve key
        raise NotImplementedError("AWS CloudHSM integration not yet implemented")
    
    def store_private_key(self, key_id: str, private_key: rsa.RSAPrivateKey) -> None:
        """Store private key in AWS CloudHSM"""
        # Placeholder - in production, use boto3 to store key
        raise NotImplementedError("AWS CloudHSM integration not yet implemented")
    
    def sign_data(self, key_id: str, data: bytes) -> bytes:
        """Sign data using AWS CloudHSM"""
        # Placeholder - in production, use AWS KMS Sign API
        raise NotImplementedError("AWS CloudHSM integration not yet implemented")
    
    def delete_key(self, key_id: str) -> None:
        """Delete key from AWS CloudHSM"""
        # Placeholder - in production, use boto3 to delete key
        raise NotImplementedError("AWS CloudHSM integration not yet implemented")


class AzureKeyVault:
    """Azure Key Vault integration (placeholder for production)"""
    
    def __init__(self, vault_url: Optional[str] = None):
        self.vault_url = vault_url
        # In production, initialize Azure Key Vault client
        # from azure.keyvault.keys import KeyClient
        # self.client = KeyClient(vault_url=vault_url, credential=credential)
    
    def get_private_key(self, key_id: str) -> rsa.RSAPrivateKey:
        """Retrieve private key from Azure Key Vault"""
        raise NotImplementedError("Azure Key Vault integration not yet implemented")
    
    def store_private_key(self, key_id: str, private_key: rsa.RSAPrivateKey) -> None:
        """Store private key in Azure Key Vault"""
        raise NotImplementedError("Azure Key Vault integration not yet implemented")
    
    def sign_data(self, key_id: str, data: bytes) -> bytes:
        """Sign data using Azure Key Vault"""
        raise NotImplementedError("Azure Key Vault integration not yet implemented")
    
    def delete_key(self, key_id: str) -> None:
        """Delete key from Azure Key Vault"""
        raise NotImplementedError("Azure Key Vault integration not yet implemented")


class HSMManager:
    """HSM manager for key operations"""
    
    def __init__(self):
        self.provider: Optional[HSMProvider] = None
        self._initialize_provider()
    
    def _initialize_provider(self):
        """Initialize HSM provider based on configuration"""
        hsm_type = getattr(settings, 'hsm_type', 'file').lower()
        
        if hsm_type == 'file':
            # Use file-based storage (development)
            hsm_key_dir = getattr(settings, 'hsm_key_dir', None)
            if hsm_key_dir is None:
                hsm_dir = settings.pki_root_dir / "hsm"
            else:
                hsm_dir = Path(hsm_key_dir) if isinstance(hsm_key_dir, str) else hsm_key_dir
            self.provider = FileBasedHSM(hsm_dir)
        elif hsm_type == 'aws':
            # AWS CloudHSM
            cluster_id = getattr(settings, 'aws_hsm_cluster_id', None)
            key_arn = getattr(settings, 'aws_hsm_key_arn', None)
            self.provider = AWSCloudHSM(cluster_id, key_arn)
        elif hsm_type == 'azure':
            # Azure Key Vault
            vault_url = getattr(settings, 'azure_key_vault_url', None)
            self.provider = AzureKeyVault(vault_url)
        else:
            # Default to file-based
            hsm_dir = settings.pki_root_dir / "hsm"
            self.provider = FileBasedHSM(hsm_dir)
    
    def get_private_key(self, key_id: str) -> rsa.RSAPrivateKey:
        """Get private key from HSM"""
        if not self.provider:
            raise ValueError("HSM provider not initialized")
        return self.provider.get_private_key(key_id)
    
    def store_private_key(self, key_id: str, private_key: rsa.RSAPrivateKey) -> None:
        """Store private key in HSM"""
        if not self.provider:
            raise ValueError("HSM provider not initialized")
        self.provider.store_private_key(key_id, private_key)
    
    def sign_data(self, key_id: str, data: bytes) -> bytes:
        """Sign data using HSM"""
        if not self.provider:
            raise ValueError("HSM provider not initialized")
        return self.provider.sign_data(key_id, data)
    
    def delete_key(self, key_id: str) -> None:
        """Delete key from HSM"""
        if not self.provider:
            raise ValueError("HSM provider not initialized")
        self.provider.delete_key(key_id)


# Global HSM manager instance
_hsm_manager: Optional[HSMManager] = None


def get_hsm_manager() -> HSMManager:
    """Get or create global HSM manager instance"""
    global _hsm_manager
    if _hsm_manager is None:
        _hsm_manager = HSMManager()
    return _hsm_manager
