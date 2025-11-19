"""
Unit tests for bundle module.
"""

import json
import zipfile
import pytest
from pathlib import Path
from vcon_zip.bundle import BundleCreator, BundleExtractor, BundleError


class TestBundleCreator:
    """Tests for BundleCreator class."""
    
    @pytest.fixture
    def sample_vcon_file(self, tmp_path):
        """Create a sample vCon file."""
        vcon_data = {
            "vcon": "0.3.0",
            "uuid": "test-uuid-1234",
            "created_at": "2023-01-01T00:00:00Z",
            "parties": [],
            "dialog": [],
            "attachments": [],
            "analysis": []
        }
        
        vcon_file = tmp_path / "test.json"
        vcon_file.write_text(json.dumps(vcon_data))
        return vcon_file
    
    def test_create_empty_bundle_fails(self, tmp_path):
        """Test creating bundle with no vCons fails."""
        creator = BundleCreator(download_files=False)
        output = tmp_path / "bundle.vconz"
        
        with pytest.raises(BundleError, match="No vCons added"):
            creator.create(output)
    
    def test_add_vcon_from_file(self, sample_vcon_file):
        """Test adding vCon from file."""
        creator = BundleCreator(download_files=False)
        creator.add_vcon(sample_vcon_file)
        
        assert len(creator.vcons) == 1
        assert creator.vcons[0].uuid == "test-uuid-1234"
    
    def test_add_vcon_from_string(self):
        """Test adding vCon from string."""
        vcon_str = json.dumps({
            "vcon": "0.3.0",
            "uuid": "string-uuid",
            "parties": [],
            "dialog": [],
            "attachments": [],
            "analysis": []
        })
        
        creator = BundleCreator(download_files=False)
        creator.add_vcon_from_string(vcon_str)
        
        assert len(creator.vcons) == 1
        assert creator.vcons[0].uuid == "string-uuid"
    
    def test_duplicate_uuid_fails(self, sample_vcon_file):
        """Test adding vCon with duplicate UUID fails."""
        creator = BundleCreator(download_files=False)
        creator.add_vcon(sample_vcon_file)
        
        with pytest.raises(BundleError, match="Duplicate vCon UUID"):
            creator.add_vcon(sample_vcon_file)
    
    def test_create_bundle_success(self, sample_vcon_file, tmp_path):
        """Test successful bundle creation."""
        creator = BundleCreator(download_files=False)
        creator.add_vcon(sample_vcon_file)
        
        output = tmp_path / "bundle.vconz"
        creator.create(output)
        
        assert output.exists()
        
        # Verify it's a valid ZIP
        with zipfile.ZipFile(output, 'r') as zf:
            assert 'manifest.json' in zf.namelist()
            assert 'vcons/test-uuid-1234.json' in zf.namelist()


class TestBundleExtractor:
    """Tests for BundleExtractor class."""
    
    @pytest.fixture
    def sample_bundle(self, tmp_path):
        """Create a sample bundle."""
        vcon_data = {
            "vcon": "0.3.0",
            "uuid": "extract-test-uuid",
            "parties": [],
            "dialog": [],
            "attachments": [],
            "analysis": []
        }
        
        manifest_data = {
            "format": "vcon-bundle",
            "version": "1.0"
        }
        
        bundle_path = tmp_path / "test.vconz"
        with zipfile.ZipFile(bundle_path, 'w') as zf:
            zf.writestr('manifest.json', json.dumps(manifest_data))
            zf.writestr('vcons/extract-test-uuid.json', json.dumps(vcon_data))
        
        return bundle_path
    
    def test_open_nonexistent_bundle_fails(self, tmp_path):
        """Test opening nonexistent bundle fails."""
        with pytest.raises(BundleError, match="Bundle file not found"):
            BundleExtractor(tmp_path / "nonexistent.vconz")
    
    def test_open_invalid_zip_fails(self, tmp_path):
        """Test opening invalid ZIP fails."""
        bad_file = tmp_path / "bad.vconz"
        bad_file.write_text("not a zip file")
        
        with pytest.raises(BundleError, match="Invalid ZIP file"):
            BundleExtractor(bad_file)
    
    def test_validate_structure_success(self, sample_bundle):
        """Test successful structure validation."""
        with BundleExtractor(sample_bundle) as extractor:
            extractor.validate_structure()  # Should not raise
    
    def test_validate_structure_missing_manifest(self, tmp_path):
        """Test validation fails without manifest."""
        bundle_path = tmp_path / "no_manifest.vconz"
        with zipfile.ZipFile(bundle_path, 'w') as zf:
            zf.writestr('vcons/test.json', '{}')
        
        with BundleExtractor(bundle_path) as extractor:
            with pytest.raises(BundleError, match="Missing manifest.json"):
                extractor.validate_structure()
    
    def test_get_manifest(self, sample_bundle):
        """Test getting manifest."""
        with BundleExtractor(sample_bundle) as extractor:
            manifest = extractor.get_manifest()
            
            assert manifest.format == "vcon-bundle"
            assert manifest.version == "1.0"
    
    def test_get_vcons(self, sample_bundle):
        """Test getting vCons list."""
        with BundleExtractor(sample_bundle) as extractor:
            vcons = extractor.get_vcons()
            
            assert len(vcons) == 1
            assert vcons[0]['uuid'] == 'extract-test-uuid'
    
    def test_get_vcon_by_uuid(self, sample_bundle):
        """Test getting vCon by UUID."""
        with BundleExtractor(sample_bundle) as extractor:
            vcon_content = extractor.get_vcon_by_uuid('extract-test-uuid')
            
            assert vcon_content is not None
            vcon_data = json.loads(vcon_content)
            assert vcon_data['uuid'] == 'extract-test-uuid'
    
    def test_get_vcon_by_uuid_not_found(self, sample_bundle):
        """Test getting nonexistent vCon returns None."""
        with BundleExtractor(sample_bundle) as extractor:
            result = extractor.get_vcon_by_uuid('nonexistent-uuid')
            
            assert result is None
    
    def test_extract_bundle(self, sample_bundle, tmp_path):
        """Test extracting bundle to directory."""
        output_dir = tmp_path / "extracted"
        
        with BundleExtractor(sample_bundle) as extractor:
            extractor.extract(output_dir)
        
        assert (output_dir / "manifest.json").exists()
        assert (output_dir / "vcons" / "extract-test-uuid.json").exists()
    
    def test_context_manager(self, sample_bundle):
        """Test BundleExtractor as context manager."""
        with BundleExtractor(sample_bundle) as extractor:
            assert extractor.zipfile is not None
        
        # ZIP should be closed after exit

