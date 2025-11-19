"""
Unit tests for hash_utils module.
"""

import pytest
from vcon_zip.hash_utils import (
    compute_hash,
    parse_content_hash,
    verify_content_hash,
    get_primary_hash,
    hash_to_filename_base,
    HashMismatchError
)


class TestComputeHash:
    """Tests for compute_hash function."""
    
    def test_sha512_hash(self):
        """Test SHA-512 hash computation."""
        data = b"Hello, World!"
        result = compute_hash(data, "sha512")
        
        assert result.startswith("sha512-")
        assert len(result) > 10
    
    def test_sha256_hash(self):
        """Test SHA-256 hash computation."""
        data = b"Hello, World!"
        result = compute_hash(data, "sha256")
        
        assert result.startswith("sha256-")
        assert len(result) > 10
    
    def test_default_algorithm(self):
        """Test default algorithm is SHA-512."""
        data = b"test data"
        result = compute_hash(data)
        
        assert result.startswith("sha512-")
    
    def test_unsupported_algorithm(self):
        """Test unsupported algorithm raises ValueError."""
        data = b"test"
        
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            compute_hash(data, "md5")
    
    def test_empty_data(self):
        """Test hashing empty data."""
        data = b""
        result = compute_hash(data, "sha512")
        
        assert result.startswith("sha512-")


class TestParseContentHash:
    """Tests for parse_content_hash function."""
    
    def test_parse_sha512(self):
        """Test parsing SHA-512 content hash."""
        content_hash = "sha512-Abc123DefGhi"
        algorithm, value = parse_content_hash(content_hash)
        
        assert algorithm == "sha512"
        assert value == "Abc123DefGhi"
    
    def test_parse_sha256(self):
        """Test parsing SHA-256 content hash."""
        content_hash = "sha256-XyzAbc"
        algorithm, value = parse_content_hash(content_hash)
        
        assert algorithm == "sha256"
        assert value == "XyzAbc"
    
    def test_invalid_format_no_dash(self):
        """Test parsing invalid format without dash."""
        with pytest.raises(ValueError, match="Invalid content hash format"):
            parse_content_hash("sha512Abc123")
    
    def test_unsupported_algorithm(self):
        """Test parsing unsupported algorithm."""
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            parse_content_hash("md5-abc123")


class TestVerifyContentHash:
    """Tests for verify_content_hash function."""
    
    def test_verify_single_hash_success(self):
        """Test successful verification with single hash."""
        data = b"test data"
        content_hash = compute_hash(data, "sha512")
        
        verify_content_hash(data, content_hash)  # Should not raise
    
    def test_verify_single_hash_failure(self):
        """Test failed verification with single hash."""
        data = b"test data"
        content_hash = "sha512-InvalidHash"
        
        with pytest.raises(HashMismatchError):
            verify_content_hash(data, content_hash)
    
    def test_verify_multiple_hashes_success(self):
        """Test successful verification with multiple hashes."""
        data = b"test data"
        hashes = [
            compute_hash(data, "sha512"),
            compute_hash(data, "sha256")
        ]
        
        verify_content_hash(data, hashes)  # Should not raise
    
    def test_verify_multiple_hashes_one_fails(self):
        """Test verification fails if any hash doesn't match."""
        data = b"test data"
        hashes = [
            compute_hash(data, "sha512"),
            "sha256-InvalidHash"
        ]
        
        with pytest.raises(HashMismatchError):
            verify_content_hash(data, hashes)


class TestGetPrimaryHash:
    """Tests for get_primary_hash function."""
    
    def test_single_hash(self):
        """Test getting primary hash from single hash."""
        content_hash = "sha512-Abc123"
        result = get_primary_hash(content_hash)
        
        assert result == content_hash
    
    def test_array_with_sha512(self):
        """Test SHA-512 is preferred in array."""
        hashes = ["sha256-Abc", "sha512-Def", "sha256-Ghi"]
        result = get_primary_hash(hashes)
        
        assert result == "sha512-Def"
    
    def test_array_without_sha512(self):
        """Test first hash is used when no SHA-512."""
        hashes = ["sha256-Abc", "sha256-Def"]
        result = get_primary_hash(hashes)
        
        assert result == "sha256-Abc"
    
    def test_empty_array(self):
        """Test empty array raises ValueError."""
        with pytest.raises(ValueError, match="Empty content hash array"):
            get_primary_hash([])


class TestHashToFilenameBase:
    """Tests for hash_to_filename_base function."""
    
    def test_basic_conversion(self):
        """Test basic hash to filename conversion."""
        content_hash = "sha512-Abc123DefGhi"
        result = hash_to_filename_base(content_hash)
        
        assert result == content_hash
    
    def test_preserves_format(self):
        """Test that format is preserved exactly."""
        content_hash = "sha256-XyZ_-123"
        result = hash_to_filename_base(content_hash)
        
        assert result == content_hash

