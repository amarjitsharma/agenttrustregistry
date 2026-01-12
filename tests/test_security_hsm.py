"""Tests for HSM integration (v0.4)"""
import pytest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import Encoding

from atr.security.hsm import FileBasedHSM, HSMManager, get_hsm_manager
from atr.core.config import settings


def test_file_based_hsm():
    """Test file-based HSM implementation"""
    import tempfile
    import shutil
    
    # Create temporary directory
    temp_dir = Path(tempfile.mkdtemp())
    try:
        hsm = FileBasedHSM(temp_dir)
        
        # Generate a test key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Store key
        hsm.store_private_key("test_key", private_key)
        
        # Retrieve key
        retrieved_key = hsm.get_private_key("test_key")
        
        # Verify keys match
        assert retrieved_key.private_numbers() == private_key.private_numbers()
        
        # Test signing
        test_data = b"test data"
        signature = hsm.sign_data("test_key", test_data)
        assert len(signature) > 0
        
        # Test deletion
        hsm.delete_key("test_key")
        
        # Verify key is deleted
        with pytest.raises(ValueError, match="not found"):
            hsm.get_private_key("test_key")
            
    finally:
        shutil.rmtree(temp_dir)


def test_hsm_manager():
    """Test HSM manager"""
    manager = get_hsm_manager()
    
    assert manager is not None
    assert manager.provider is not None
    assert isinstance(manager.provider, FileBasedHSM)


def test_hsm_manager_key_operations():
    """Test HSM manager key operations"""
    import tempfile
    import shutil
    
    temp_dir = Path(tempfile.mkdtemp())
    try:
        # Create HSM with custom directory
        from atr.security.hsm import HSMManager, FileBasedHSM
        
        # Temporarily override settings
        original_hsm_type = settings.hsm_type
        original_hsm_key_dir = getattr(settings, 'hsm_key_dir', None)
        
        settings.hsm_type = "file"
        settings.hsm_key_dir = temp_dir
        
        manager = HSMManager()
        
        # Generate and store key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        manager.store_private_key("test_key", private_key)
        
        # Retrieve key
        retrieved_key = manager.get_private_key("test_key")
        assert retrieved_key.private_numbers() == private_key.private_numbers()
        
        # Test signing
        test_data = b"test data"
        signature = manager.sign_data("test_key", test_data)
        assert len(signature) > 0
        
        # Restore settings
        settings.hsm_type = original_hsm_type
        if original_hsm_key_dir is not None:
            settings.hsm_key_dir = original_hsm_key_dir
            
    finally:
        shutil.rmtree(temp_dir)
