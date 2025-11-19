"""
Hash utilities for vCon content hash computation and verification.

Supports SHA-512 and SHA-256 algorithms as specified in the vCon specification.
"""

import base64
import hashlib
from typing import Union, List, Tuple


class HashMismatchError(Exception):
    """Raised when content hash verification fails."""
    
    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(f"Hash mismatch: expected {expected}, got {actual}")


def compute_hash(data: bytes, algorithm: str = "sha512") -> str:
    """
    Compute content hash of data using specified algorithm.
    
    Args:
        data: Binary data to hash
        algorithm: Hash algorithm (sha512 or sha256)
        
    Returns:
        Content hash in format: algorithm-base64url
        
    Raises:
        ValueError: If algorithm is not supported
    """
    algorithm = algorithm.lower()
    
    if algorithm == "sha512":
        hash_obj = hashlib.sha512(data)
    elif algorithm == "sha256":
        hash_obj = hashlib.sha256(data)
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    # Encode as base64url (URL-safe base64 without padding)
    hash_bytes = hash_obj.digest()
    hash_b64 = base64.urlsafe_b64encode(hash_bytes).decode('ascii').rstrip('=')
    
    return f"{algorithm}-{hash_b64}"


def parse_content_hash(content_hash: str) -> Tuple[str, str]:
    """
    Parse a content hash string into algorithm and value.
    
    Args:
        content_hash: Content hash in format "algorithm-base64url"
        
    Returns:
        Tuple of (algorithm, base64url_value)
        
    Raises:
        ValueError: If content_hash format is invalid
    """
    if '-' not in content_hash:
        raise ValueError(f"Invalid content hash format: {content_hash}")
    
    parts = content_hash.split('-', 1)
    if len(parts) != 2:
        raise ValueError(f"Invalid content hash format: {content_hash}")
    
    algorithm, hash_value = parts
    algorithm = algorithm.lower()
    
    if algorithm not in ('sha512', 'sha256'):
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    return algorithm, hash_value


def verify_content_hash(data: bytes, content_hash: Union[str, List[str]]) -> None:
    """
    Verify data against content hash(es).
    
    Args:
        data: Binary data to verify
        content_hash: Single content hash string or list of content hashes
        
    Raises:
        HashMismatchError: If any hash does not match
        ValueError: If content_hash format is invalid
    """
    # Handle both single hash and array of hashes
    hashes = [content_hash] if isinstance(content_hash, str) else content_hash
    
    for hash_str in hashes:
        algorithm, expected_value = parse_content_hash(hash_str)
        computed_hash = compute_hash(data, algorithm)
        
        if computed_hash != hash_str:
            raise HashMismatchError(hash_str, computed_hash)


def get_primary_hash(content_hash: Union[str, List[str]]) -> str:
    """
    Get the primary hash from a content hash or array of hashes.
    
    Per spec: If SHA-512 is present in array, use it as primary regardless of position.
    Otherwise, use the first hash in the array.
    
    Args:
        content_hash: Single content hash string or list of content hashes
        
    Returns:
        Primary content hash string
    """
    if isinstance(content_hash, str):
        return content_hash
    
    if not content_hash:
        raise ValueError("Empty content hash array")
    
    # Prefer SHA-512 if present
    for hash_str in content_hash:
        algorithm, _ = parse_content_hash(hash_str)
        if algorithm == 'sha512':
            return hash_str
    
    # Otherwise use first
    return content_hash[0]


def hash_to_filename_base(content_hash: str) -> str:
    """
    Convert content hash to filename base (without extension).
    
    Args:
        content_hash: Content hash in format "algorithm-base64url"
        
    Returns:
        Filename base suitable for filesystem (e.g., "sha512-AbC123...")
    """
    # Content hash is already in the correct format for filenames
    # base64url is filesystem-safe
    return content_hash

