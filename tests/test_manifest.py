"""
Unit tests for manifest module.
"""

import json
import pytest
from pathlib import Path
from vcon_zip.manifest import Manifest, ManifestError


class TestManifest:
    """Tests for Manifest class."""
    
    def test_create_default_manifest(self):
        """Test creating manifest with defaults."""
        manifest = Manifest()
        
        assert manifest.format == "vcon-bundle"
        assert manifest.version == "1.0"
    
    def test_create_custom_version(self):
        """Test creating manifest with custom version."""
        manifest = Manifest(version="2.0")
        
        assert manifest.version == "2.0"
    
    def test_invalid_format_raises_error(self):
        """Test invalid format raises ManifestError."""
        with pytest.raises(ManifestError, match="Invalid format"):
            Manifest(format="invalid-format")
    
    def test_to_dict(self):
        """Test converting manifest to dictionary."""
        manifest = Manifest()
        result = manifest.to_dict()
        
        assert result == {
            "format": "vcon-bundle",
            "version": "1.0"
        }
    
    def test_to_json(self):
        """Test converting manifest to JSON."""
        manifest = Manifest()
        result = manifest.to_json()
        
        data = json.loads(result)
        assert data["format"] == "vcon-bundle"
        assert data["version"] == "1.0"
    
    def test_from_dict(self):
        """Test creating manifest from dictionary."""
        data = {"format": "vcon-bundle", "version": "1.0"}
        manifest = Manifest.from_dict(data)
        
        assert manifest.format == "vcon-bundle"
        assert manifest.version == "1.0"
    
    def test_from_dict_missing_format(self):
        """Test from_dict raises error if format missing."""
        data = {"version": "1.0"}
        
        with pytest.raises(ManifestError, match="Missing required field: format"):
            Manifest.from_dict(data)
    
    def test_from_dict_missing_version(self):
        """Test from_dict raises error if version missing."""
        data = {"format": "vcon-bundle"}
        
        with pytest.raises(ManifestError, match="Missing required field: version"):
            Manifest.from_dict(data)
    
    def test_from_json(self):
        """Test creating manifest from JSON string."""
        json_str = '{"format": "vcon-bundle", "version": "1.0"}'
        manifest = Manifest.from_json(json_str)
        
        assert manifest.format == "vcon-bundle"
        assert manifest.version == "1.0"
    
    def test_from_json_invalid(self):
        """Test from_json raises error for invalid JSON."""
        json_str = '{"invalid json'
        
        with pytest.raises(ManifestError, match="Invalid JSON"):
            Manifest.from_json(json_str)
    
    def test_save_and_load(self, tmp_path):
        """Test saving and loading manifest."""
        manifest = Manifest()
        manifest_file = tmp_path / "manifest.json"
        
        manifest.save(manifest_file)
        loaded = Manifest.load(manifest_file)
        
        assert loaded.format == manifest.format
        assert loaded.version == manifest.version
    
    def test_load_nonexistent_file(self, tmp_path):
        """Test loading nonexistent file raises error."""
        manifest_file = tmp_path / "nonexistent.json"
        
        with pytest.raises(ManifestError, match="Manifest file not found"):
            Manifest.load(manifest_file)
    
    def test_is_version_supported_v1(self):
        """Test version 1.0 is supported."""
        manifest = Manifest(version="1.0")
        
        assert manifest.is_version_supported()
    
    def test_is_version_supported_unsupported(self):
        """Test unsupported version returns False."""
        manifest = Manifest.__new__(Manifest)
        manifest.format = "vcon-bundle"
        manifest.version = "99.0"
        
        assert not manifest.is_version_supported()

