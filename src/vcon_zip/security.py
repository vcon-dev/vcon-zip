"""
Security handling for vCon JWS signature verification and JWE decryption.

Provides functionality for:
- JWS (JSON Web Signature) verification
- JWE (JSON Web Encryption) decryption
- Key management for cryptographic operations
"""

import json
from typing import Optional, Any, Dict
from jose import jws, jwe, jwt
from jose.exceptions import JWSError, JWEError, JWTError


class SecurityError(Exception):
    """Base exception for security operations."""
    pass


class SignatureVerificationError(SecurityError):
    """Raised when JWS signature verification fails."""
    pass


class DecryptionError(SecurityError):
    """Raised when JWE decryption fails."""
    pass


class JWSVerifier:
    """
    Verifies JWS (JSON Web Signature) signed vCons.
    
    Supports various JWS algorithms as defined in the vCon specification.
    """
    
    def __init__(self, public_key: Optional[Any] = None, verify: bool = True):
        """
        Initialize JWS verifier.
        
        Args:
            public_key: Public key for signature verification (RSA, EC, etc.)
            verify: Whether to verify signatures (set False for testing)
        """
        self.public_key = public_key
        self.verify = verify
    
    def verify_signature(self, jws_token: str) -> Dict[str, Any]:
        """
        Verify JWS signature and return payload.
        
        Args:
            jws_token: JWS token as JSON string or compact format
            
        Returns:
            Dictionary containing verified payload
            
        Raises:
            SignatureVerificationError: If signature verification fails
        """
        if not self.verify:
            # Skip verification (extract payload without verification)
            return self._extract_payload_unverified(jws_token)
        
        if self.public_key is None:
            raise SignatureVerificationError("Public key required for signature verification")
        
        try:
            # Verify and decode JWS
            payload = jws.verify(jws_token, self.public_key, algorithms=['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'])
            return json.loads(payload)
        except JWSError as e:
            raise SignatureVerificationError(f"JWS signature verification failed: {e}")
        except Exception as e:
            raise SignatureVerificationError(f"Error verifying JWS: {e}")
    
    def _extract_payload_unverified(self, jws_token: str) -> Dict[str, Any]:
        """
        Extract payload from JWS without verification (for inspection only).
        
        Args:
            jws_token: JWS token as JSON string
            
        Returns:
            Dictionary containing unverified payload
            
        Raises:
            SignatureVerificationError: If extraction fails
        """
        try:
            # Parse JWS JSON
            if jws_token.strip().startswith('{'):
                jws_data = json.loads(jws_token)
                if 'payload' in jws_data:
                    import base64
                    payload_b64 = jws_data['payload']
                    # Add padding if needed
                    padding = 4 - (len(payload_b64) % 4)
                    if padding != 4:
                        payload_b64 += '=' * padding
                    payload_bytes = base64.urlsafe_b64decode(payload_b64)
                    return json.loads(payload_bytes.decode('utf-8'))
            
            # Try compact format
            parts = jws_token.split('.')
            if len(parts) == 3:
                import base64
                payload_b64 = parts[1]
                padding = 4 - (len(payload_b64) % 4)
                if padding != 4:
                    payload_b64 += '=' * padding
                payload_bytes = base64.urlsafe_b64decode(payload_b64)
                return json.loads(payload_bytes.decode('utf-8'))
            
            raise SignatureVerificationError("Invalid JWS format")
        except Exception as e:
            raise SignatureVerificationError(f"Failed to extract JWS payload: {e}")
    
    def extract_payload(self, jws_token: str) -> str:
        """
        Extract payload from JWS as string.
        
        Args:
            jws_token: JWS token
            
        Returns:
            Payload as JSON string
            
        Raises:
            SignatureVerificationError: If extraction fails
        """
        payload_dict = self.verify_signature(jws_token) if self.verify else self._extract_payload_unverified(jws_token)
        return json.dumps(payload_dict)


class JWEDecryptor:
    """
    Decrypts JWE (JSON Web Encryption) encrypted vCons.
    
    Supports various JWE algorithms and encryption methods.
    """
    
    def __init__(self, private_key: Any):
        """
        Initialize JWE decryptor.
        
        Args:
            private_key: Private key for decryption (RSA, EC, etc.)
        """
        if private_key is None:
            raise DecryptionError("Private key required for JWE decryption")
        
        self.private_key = private_key
    
    def decrypt(self, jwe_token: str) -> str:
        """
        Decrypt JWE and return plaintext.
        
        Args:
            jwe_token: JWE token as JSON string or compact format
            
        Returns:
            Decrypted plaintext (may be JSON, could be nested JWS)
            
        Raises:
            DecryptionError: If decryption fails
        """
        try:
            # Decrypt JWE
            plaintext = jwe.decrypt(jwe_token, self.private_key)
            
            # Return as string (caller will parse if needed)
            if isinstance(plaintext, bytes):
                return plaintext.decode('utf-8')
            return plaintext
        except JWEError as e:
            raise DecryptionError(f"JWE decryption failed: {e}")
        except Exception as e:
            raise DecryptionError(f"Error decrypting JWE: {e}")
    
    def decrypt_to_dict(self, jwe_token: str) -> Dict[str, Any]:
        """
        Decrypt JWE and parse as JSON.
        
        Args:
            jwe_token: JWE token
            
        Returns:
            Decrypted content as dictionary
            
        Raises:
            DecryptionError: If decryption or parsing fails
        """
        plaintext = self.decrypt(jwe_token)
        try:
            return json.loads(plaintext)
        except json.JSONDecodeError as e:
            raise DecryptionError(f"Decrypted content is not valid JSON: {e}")


class KeyManager:
    """
    Manages cryptographic keys for JWS/JWE operations.
    
    Provides utilities for loading and managing keys from various formats.
    """
    
    @staticmethod
    def load_key_from_file(file_path: str, password: Optional[bytes] = None) -> Any:
        """
        Load a cryptographic key from file.
        
        Args:
            file_path: Path to key file (PEM format)
            password: Optional password for encrypted keys
            
        Returns:
            Key object suitable for JWS/JWE operations
            
        Raises:
            SecurityError: If key loading fails
        """
        try:
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.backends import default_backend
            
            with open(file_path, 'rb') as f:
                key_data = f.read()
            
            # Try loading as private key
            try:
                key = serialization.load_pem_private_key(
                    key_data,
                    password=password,
                    backend=default_backend()
                )
                return key
            except:
                pass
            
            # Try loading as public key
            try:
                key = serialization.load_pem_public_key(
                    key_data,
                    backend=default_backend()
                )
                return key
            except:
                pass
            
            raise SecurityError("Unable to load key from file")
        except Exception as e:
            raise SecurityError(f"Error loading key: {e}")
    
    @staticmethod
    def load_jwk(jwk_dict: Dict[str, Any]) -> Any:
        """
        Load key from JWK (JSON Web Key) format.
        
        Args:
            jwk_dict: JWK as dictionary
            
        Returns:
            Key object
            
        Raises:
            SecurityError: If JWK loading fails
        """
        try:
            from jose.backends.cryptography_backend import CryptographyKey
            return CryptographyKey(jwk_dict, algorithm='RS256')
        except Exception as e:
            raise SecurityError(f"Error loading JWK: {e}")

