"""
Unit tests for file_resolver module.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests
from vcon_zip.file_resolver import (
    FileResolver,
    FileResolverError,
    NetworkError,
    AccessDeniedError
)
from vcon_zip.hash_utils import compute_hash


class TestFileResolver:
    """Tests for FileResolver class."""
    
    @pytest.fixture
    def resolver(self):
        """Create FileResolver instance."""
        return FileResolver()
    
    def test_validate_url_https(self, resolver):
        """Test HTTPS URL validation passes."""
        resolver._validate_url("https://example.com/file.wav")  # Should not raise
    
    def test_validate_url_http_fails(self, resolver):
        """Test HTTP URL validation fails."""
        with pytest.raises(FileResolverError, match="Only HTTPS URLs are supported"):
            resolver._validate_url("http://example.com/file.wav")
    
    def test_determine_extension_from_mimetype(self, resolver):
        """Test extension determination from MIME type."""
        ext = resolver.determine_extension(mimetype="audio/wav")
        assert ext == ".wav"
        
        ext = resolver.determine_extension(mimetype="application/pdf")
        assert ext == ".pdf"
    
    def test_determine_extension_from_url(self, resolver):
        """Test extension determination from URL."""
        ext = resolver.determine_extension(
            url="https://example.com/file.mp3"
        )
        assert ext == ".mp3"
    
    def test_determine_extension_from_magic_bytes(self, resolver):
        """Test extension determination from magic bytes."""
        # WAV file signature
        wav_data = b'RIFF\x00\x00\x00\x00WAVEfmt '
        ext = resolver.determine_extension(data=wav_data)
        assert ext == ".wav"
        
        # PDF file signature (needs at least 12 bytes)
        pdf_data = b'%PDF-1.4\n%\xaa\xbb\xcc'
        ext = resolver.determine_extension(data=pdf_data)
        assert ext == ".pdf"
    
    def test_determine_extension_fallback_to_bin(self, resolver):
        """Test extension falls back to .bin."""
        ext = resolver.determine_extension()
        assert ext == ".bin"
    
    def test_generate_filename(self, resolver):
        """Test filename generation."""
        data = b"test content"
        content_hash = compute_hash(data, "sha512")
        
        filename = resolver.generate_filename(
            content_hash=content_hash,
            mimetype="audio/wav"
        )
        
        assert filename.startswith("sha512-")
        assert filename.endswith(".wav")
    
    @patch('vcon_zip.file_resolver.requests.Session.get')
    def test_download_with_retry_success(self, mock_get, resolver):
        """Test successful download."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.content = b"test file content"
        mock_get.return_value = mock_response
        
        data = resolver._download_with_retry("https://example.com/file.txt")
        
        assert data == b"test file content"
        mock_get.assert_called_once()
    
    @patch('vcon_zip.file_resolver.requests.Session.get')
    def test_download_with_retry_403_no_retry(self, mock_get, resolver):
        """Test 403 error does not retry."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response
        
        with pytest.raises(AccessDeniedError):
            resolver._download_with_retry("https://example.com/file.txt")
        
        mock_get.assert_called_once()  # Should not retry
    
    @patch('vcon_zip.file_resolver.requests.Session.get')
    def test_download_with_retry_network_error(self, mock_get, resolver):
        """Test network error triggers retry."""
        mock_get.side_effect = requests.ConnectionError("Network error")
        
        with pytest.raises(NetworkError):
            resolver._download_with_retry("https://example.com/file.txt")
        
        assert mock_get.call_count == 3  # Default max_retries
    
    def test_context_manager(self):
        """Test FileResolver as context manager."""
        with FileResolver() as resolver:
            assert resolver.session is not None
        
        # Session should be closed after exit
    
    def test_detect_extension_from_magic_mp4(self, resolver):
        """Test MP4 detection from magic bytes."""
        # MP4 has 'ftyp' at offset 4
        mp4_data = b'\x00\x00\x00\x18ftypmp42'
        ext = resolver._detect_extension_from_magic(mp4_data)
        assert ext == ".mp4"
    
    def test_detect_extension_from_magic_json(self, resolver):
        """Test JSON detection from magic bytes."""
        json_data = b'{"key": "value"}'
        ext = resolver._detect_extension_from_magic(json_data)
        assert ext == ".json"

