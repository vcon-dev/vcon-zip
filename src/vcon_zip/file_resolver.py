"""
External file resolution for vCon Zip Bundle creation.

Handles:
- Downloading files from HTTPS URLs
- Content hash verification
- File extension determination
- Retry logic with exponential backoff
"""

import time
import mimetypes
from typing import Optional, Tuple
from pathlib import Path
import requests
from urllib.parse import urlparse

from .hash_utils import verify_content_hash, get_primary_hash, hash_to_filename_base


class FileResolverError(Exception):
    """Base exception for file resolution errors."""
    pass


class NetworkError(FileResolverError):
    """Raised when network operations fail."""
    pass


class AccessDeniedError(FileResolverError):
    """Raised when access to URL is denied (403/401)."""
    pass


class FileResolver:
    """
    Resolves external file references from vCons.
    
    Downloads files from HTTPS URLs, verifies content hashes,
    and determines appropriate file extensions.
    """
    
    # MIME type to extension mapping (common types)
    MIME_TO_EXT = {
        'audio/wav': '.wav',
        'audio/x-wav': '.wav',
        'audio/mpeg': '.mp3',
        'audio/mp4': '.m4a',
        'audio/ogg': '.ogg',
        'video/mp4': '.mp4',
        'video/mpeg': '.mpeg',
        'video/quicktime': '.mov',
        'video/x-msvideo': '.avi',
        'application/pdf': '.pdf',
        'application/json': '.json',
        'text/plain': '.txt',
        'text/html': '.html',
        'image/jpeg': '.jpg',
        'image/png': '.png',
        'image/gif': '.gif',
        'image/webp': '.webp',
    }
    
    def __init__(
        self,
        max_retries: int = 3,
        initial_backoff: float = 1.0,
        timeout: int = 30
    ):
        """
        Initialize file resolver.
        
        Args:
            max_retries: Maximum number of retry attempts
            initial_backoff: Initial backoff time in seconds
            timeout: Request timeout in seconds
        """
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'vcon-zip/1.0.0'
        })
    
    def download_file(self, url: str, content_hash: any) -> Tuple[bytes, str]:
        """
        Download file from URL and verify against content hash.
        
        Args:
            url: HTTPS URL to download from
            content_hash: Expected content hash (string or list)
            
        Returns:
            Tuple of (file_data, filename) where filename includes extension
            
        Raises:
            FileResolverError: If download or verification fails
            NetworkError: If network operations fail after retries
            AccessDeniedError: If access is denied (401/403)
        """
        # Validate URL
        self._validate_url(url)
        
        # Download with retry logic
        data = self._download_with_retry(url)
        
        # Verify content hash
        try:
            verify_content_hash(data, content_hash)
        except Exception as e:
            raise FileResolverError(f"Hash verification failed for {url}: {e}")
        
        # Generate filename
        filename = self.generate_filename(content_hash, mimetype=None, url=url, data=data)
        
        return data, filename
    
    def _validate_url(self, url: str) -> None:
        """
        Validate that URL is HTTPS.
        
        Args:
            url: URL to validate
            
        Raises:
            FileResolverError: If URL is not HTTPS
        """
        parsed = urlparse(url)
        if parsed.scheme != 'https':
            raise FileResolverError(f"Only HTTPS URLs are supported: {url}")
    
    def _download_with_retry(self, url: str) -> bytes:
        """
        Download file with exponential backoff retry logic.
        
        Args:
            url: URL to download from
            
        Returns:
            Downloaded file data
            
        Raises:
            NetworkError: If download fails after all retries
            AccessDeniedError: If access is denied (no retry)
        """
        backoff = self.initial_backoff
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                # Handle access denied (don't retry)
                if response.status_code in (401, 403):
                    raise AccessDeniedError(
                        f"Access denied to {url}: HTTP {response.status_code}"
                    )
                
                response.raise_for_status()
                return response.content
                
            except AccessDeniedError:
                raise
            except requests.RequestException as e:
                last_error = e
                
                if attempt < self.max_retries - 1:
                    time.sleep(backoff)
                    backoff *= 2  # Exponential backoff
                else:
                    raise NetworkError(
                        f"Failed to download {url} after {self.max_retries} attempts: {last_error}"
                    )
        
        raise NetworkError(f"Failed to download {url}: {last_error}")
    
    def determine_extension(
        self,
        mimetype: Optional[str] = None,
        url: Optional[str] = None,
        data: Optional[bytes] = None
    ) -> str:
        """
        Determine file extension using priority: MIME type → magic bytes → URL → .bin
        
        Args:
            mimetype: MIME type from vCon
            url: Original URL
            data: File data for magic byte inspection
            
        Returns:
            File extension including leading dot (e.g., '.wav')
        """
        # 1. Try MIME type
        if mimetype:
            ext = self.MIME_TO_EXT.get(mimetype.lower())
            if ext:
                return ext
            
            # Try standard mimetypes library
            ext = mimetypes.guess_extension(mimetype)
            if ext:
                return ext
        
        # 2. Try magic bytes
        if data:
            ext = self._detect_extension_from_magic(data)
            if ext:
                return ext
        
        # 3. Try URL extension
        if url:
            parsed = urlparse(url)
            path = Path(parsed.path)
            if path.suffix:
                return path.suffix
        
        # 4. Default to .bin
        return '.bin'
    
    def _detect_extension_from_magic(self, data: bytes) -> Optional[str]:
        """
        Detect file extension from magic bytes (file header).
        
        Args:
            data: File data
            
        Returns:
            File extension or None if unknown
        """
        if len(data) < 12:
            return None
        
        # Check common file signatures
        signatures = {
            b'RIFF': '.wav',  # WAV files (check for WAVE after 8 bytes)
            b'\xff\xfb': '.mp3',  # MP3
            b'\xff\xf3': '.mp3',  # MP3
            b'\xff\xf2': '.mp3',  # MP3
            b'ID3': '.mp3',  # MP3 with ID3
            b'ftyp': '.mp4',  # MP4 (at offset 4)
            b'%PDF': '.pdf',  # PDF
            b'\x89PNG': '.png',  # PNG
            b'\xff\xd8\xff': '.jpg',  # JPEG
            b'GIF87a': '.gif',  # GIF
            b'GIF89a': '.gif',  # GIF
            b'{': '.json',  # JSON (probable)
        }
        
        # Check first 12 bytes
        header = data[:12]
        
        for sig, ext in signatures.items():
            if header.startswith(sig):
                # Special case for WAV: verify WAVE marker
                if ext == '.wav' and len(data) >= 12:
                    if data[8:12] == b'WAVE':
                        return '.wav'
                    continue
                return ext
        
        # Check for ftyp at offset 4 (MP4)
        if len(data) >= 12 and data[4:8] == b'ftyp':
            return '.mp4'
        
        return None
    
    def generate_filename(
        self,
        content_hash: any,
        mimetype: Optional[str] = None,
        url: Optional[str] = None,
        data: Optional[bytes] = None
    ) -> str:
        """
        Generate filename for bundled file.
        
        Format: [hash-algorithm]-[base64url].[extension]
        
        Args:
            content_hash: Content hash (string or list)
            mimetype: Optional MIME type
            url: Optional original URL
            data: Optional file data
            
        Returns:
            Complete filename
        """
        # Get primary hash
        primary_hash = get_primary_hash(content_hash)
        
        # Get base filename from hash
        base_name = hash_to_filename_base(primary_hash)
        
        # Determine extension
        extension = self.determine_extension(mimetype, url, data)
        
        return f"{base_name}{extension}"
    
    def close(self) -> None:
        """Close the HTTP session."""
        self.session.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

