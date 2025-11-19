"""
Unit tests for vcon_parser module.
"""

import json
import base64
import pytest
from vcon_zip.vcon_parser import (
    VConParser,
    SecurityForm,
    VConParserError,
    ExternalReference,
    ParsedVCon
)


class TestVConParser:
    """Tests for VConParser class."""
    
    @pytest.fixture
    def sample_unsigned_vcon(self):
        """Sample unsigned vCon."""
        return json.dumps({
            "vcon": "0.3.0",
            "uuid": "01234567-89ab-cdef-0123-456789abcdef",
            "created_at": "2023-01-01T00:00:00Z",
            "parties": [],
            "dialog": [
                {
                    "type": "recording",
                    "start": "2023-01-01T00:00:00Z",
                    "url": "https://example.com/audio.wav",
                    "content_hash": "sha512-TestHash123",
                    "mimetype": "audio/wav"
                }
            ],
            "attachments": [],
            "analysis": []
        })
    
    @pytest.fixture
    def sample_jws_vcon(self):
        """Sample JWS signed vCon."""
        payload = {
            "vcon": "0.3.0",
            "uuid": "01234567-89ab-cdef-0123-456789abcdef",
            "created_at": "2023-01-01T00:00:00Z",
            "parties": [],
            "dialog": [],
            "attachments": [],
            "analysis": []
        }
        payload_str = json.dumps(payload)
        payload_b64 = base64.urlsafe_b64encode(payload_str.encode()).decode().rstrip('=')
        
        return json.dumps({
            "protected": "eyJhbGciOiJSUzI1NiJ9",
            "payload": payload_b64,
            "signature": "fake-signature"
        })
    
    def test_parse_unsigned_vcon(self, sample_unsigned_vcon):
        """Test parsing unsigned vCon."""
        parser = VConParser()
        result = parser.parse(sample_unsigned_vcon)
        
        assert result.security_form == SecurityForm.UNSIGNED
        assert result.uuid == "01234567-89ab-cdef-0123-456789abcdef"
        assert len(result.external_references) == 1
        assert result.external_references[0].url == "https://example.com/audio.wav"
    
    def test_parse_jws_vcon(self, sample_jws_vcon):
        """Test parsing JWS signed vCon."""
        parser = VConParser()
        result = parser.parse(sample_jws_vcon)
        
        assert result.security_form == SecurityForm.SIGNED
        assert result.uuid == "01234567-89ab-cdef-0123-456789abcdef"
    
    def test_parse_invalid_json(self):
        """Test parsing invalid JSON raises error."""
        parser = VConParser()
        
        with pytest.raises(VConParserError, match="Invalid JSON"):
            parser.parse("{invalid json")
    
    def test_extract_external_references_dialog(self, sample_unsigned_vcon):
        """Test extracting external references from dialog."""
        parser = VConParser()
        result = parser.parse(sample_unsigned_vcon)
        
        assert len(result.external_references) == 1
        ref = result.external_references[0]
        assert ref.reference_type == "dialog"
        assert ref.url == "https://example.com/audio.wav"
        assert ref.content_hash == "sha512-TestHash123"
        assert ref.mimetype == "audio/wav"
    
    def test_extract_external_references_multiple_types(self):
        """Test extracting references from multiple arrays."""
        vcon_data = {
            "vcon": "0.3.0",
            "uuid": "test-uuid",
            "parties": [],
            "dialog": [
                {
                    "url": "https://example.com/dialog.wav",
                    "content_hash": "sha512-Dialog"
                }
            ],
            "attachments": [
                {
                    "url": "https://example.com/attachment.pdf",
                    "content_hash": "sha512-Attachment"
                }
            ],
            "analysis": [
                {
                    "url": "https://example.com/analysis.json",
                    "content_hash": "sha512-Analysis"
                }
            ]
        }
        
        parser = VConParser()
        result = parser.parse(json.dumps(vcon_data))
        
        assert len(result.external_references) == 3
        
        types = [ref.reference_type for ref in result.external_references]
        assert "dialog" in types
        assert "attachment" in types
        assert "analysis" in types
    
    def test_parse_vcon_missing_uuid(self):
        """Test parsing vCon without UUID raises error."""
        vcon_data = {
            "vcon": "0.3.0",
            "parties": []
        }
        
        parser = VConParser()
        
        with pytest.raises(VConParserError, match="missing required 'uuid' field"):
            parser.parse(json.dumps(vcon_data))
    
    def test_detect_security_form_unsigned(self):
        """Test detecting unsigned security form."""
        parser = VConParser()
        data = {"vcon": "0.3.0", "uuid": "test"}
        
        form = parser._detect_security_form(data)
        
        assert form == SecurityForm.UNSIGNED
    
    def test_detect_security_form_signed(self):
        """Test detecting signed security form."""
        parser = VConParser()
        data = {"protected": "header", "payload": "data", "signature": "sig"}
        
        form = parser._detect_security_form(data)
        
        assert form == SecurityForm.SIGNED
    
    def test_detect_security_form_encrypted(self):
        """Test detecting encrypted security form."""
        parser = VConParser()
        data = {"protected": "header", "encrypted_key": "key", "ciphertext": "data"}
        
        form = parser._detect_security_form(data)
        
        assert form == SecurityForm.ENCRYPTED

