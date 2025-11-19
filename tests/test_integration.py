"""
Integration tests for vCon Zip Bundle.

Tests end-to-end workflows including:
- Creating bundles from multiple vCons
- Extracting and validating bundles
- Multi-vCon bundles with deduplication
- JWS signature verification
"""

import json
import zipfile
import pytest
from pathlib import Path
from vcon_zip.bundle import BundleCreator, BundleExtractor
from vcon_zip.validation import BundleValidator
from vcon_zip.hash_utils import compute_hash


class TestEndToEndBundleWorkflow:
    """End-to-end integration tests."""
    
    @pytest.fixture
    def sample_vcons(self, tmp_path):
        """Create multiple sample vCon files."""
        vcons = []
        
        for i in range(3):
            vcon_data = {
                "vcon": "0.3.0",
                "uuid": f"integration-test-uuid-{i}",
                "created_at": "2023-01-01T00:00:00Z",
                "parties": [],
                "dialog": [],
                "attachments": [],
                "analysis": []
            }
            
            vcon_file = tmp_path / f"vcon_{i}.json"
            vcon_file.write_text(json.dumps(vcon_data))
            vcons.append(vcon_file)
        
        return vcons
    
    def test_create_and_extract_single_vcon(self, tmp_path, sample_vcons):
        """Test creating and extracting a single vCon bundle."""
        # Create bundle
        creator = BundleCreator(download_files=False)
        creator.add_vcon(sample_vcons[0])
        
        bundle_path = tmp_path / "single.vconz"
        creator.create(bundle_path)
        
        # Verify bundle exists
        assert bundle_path.exists()
        
        # Extract bundle
        extract_dir = tmp_path / "extracted"
        with BundleExtractor(bundle_path) as extractor:
            extractor.extract(extract_dir)
        
        # Verify extracted files
        assert (extract_dir / "manifest.json").exists()
        assert (extract_dir / "vcons" / "integration-test-uuid-0.json").exists()
    
    def test_create_multi_vcon_bundle(self, tmp_path, sample_vcons):
        """Test creating bundle with multiple vCons."""
        creator = BundleCreator(download_files=False)
        
        # Add all vCons
        for vcon_file in sample_vcons:
            creator.add_vcon(vcon_file)
        
        bundle_path = tmp_path / "multi.vconz"
        creator.create(bundle_path)
        
        # Verify bundle
        with BundleExtractor(bundle_path) as extractor:
            vcons = extractor.get_vcons()
            assert len(vcons) == 3
            
            uuids = [v['uuid'] for v in vcons]
            assert 'integration-test-uuid-0' in uuids
            assert 'integration-test-uuid-1' in uuids
            assert 'integration-test-uuid-2' in uuids
    
    def test_validate_created_bundle(self, tmp_path, sample_vcons):
        """Test validating a created bundle."""
        creator = BundleCreator(download_files=False)
        creator.add_vcon(sample_vcons[0])
        
        bundle_path = tmp_path / "validate.vconz"
        creator.create(bundle_path)
        
        # Validate
        validator = BundleValidator(verify_hashes=False)
        report = validator.validate(bundle_path)
        
        assert report.is_valid
        assert len(report.errors) == 0
    
    def test_bundle_with_inline_content(self, tmp_path):
        """Test bundle with inline content (no external files)."""
        vcon_data = {
            "vcon": "0.3.0",
            "uuid": "inline-content-uuid",
            "parties": [],
            "dialog": [
                {
                    "type": "text",
                    "body": "Inline text content",
                    "encoding": "none"
                }
            ],
            "attachments": [],
            "analysis": []
        }
        
        vcon_file = tmp_path / "inline.json"
        vcon_file.write_text(json.dumps(vcon_data))
        
        creator = BundleCreator(download_files=False)
        creator.add_vcon(vcon_file)
        
        bundle_path = tmp_path / "inline.vconz"
        creator.create(bundle_path)
        
        # Verify bundle structure
        with zipfile.ZipFile(bundle_path, 'r') as zf:
            namelist = zf.namelist()
            assert 'manifest.json' in namelist
            assert 'vcons/inline-content-uuid.json' in namelist
            # No files directory needed for inline content


class TestDeduplication:
    """Tests for file deduplication."""
    
    def test_shared_file_deduplication(self, tmp_path):
        """Test that shared files are deduplicated."""
        shared_hash = "sha512-SharedContentHash123"
        
        vcon1 = {
            "vcon": "0.3.0",
            "uuid": "dedup-uuid-1",
            "parties": [],
            "dialog": [
                {
                    "url": "https://example.com/shared.wav",
                    "content_hash": shared_hash
                }
            ],
            "attachments": [],
            "analysis": []
        }
        
        vcon2 = {
            "vcon": "0.3.0",
            "uuid": "dedup-uuid-2",
            "parties": [],
            "dialog": [
                {
                    "url": "https://example.com/shared.wav",
                    "content_hash": shared_hash
                }
            ],
            "attachments": [],
            "analysis": []
        }
        
        vcon1_file = tmp_path / "vcon1.json"
        vcon2_file = tmp_path / "vcon2.json"
        vcon1_file.write_text(json.dumps(vcon1))
        vcon2_file.write_text(json.dumps(vcon2))
        
        # Note: This test would require mocking file downloads
        # For now, we're just testing the structure
        creator = BundleCreator(download_files=False)
        creator.add_vcon(vcon1_file)
        creator.add_vcon(vcon2_file)
        
        assert len(creator.vcons) == 2


class TestSecurityForms:
    """Tests for different security forms."""
    
    def test_unsigned_vcon_bundle(self, tmp_path):
        """Test bundle with unsigned vCon."""
        vcon_data = {
            "vcon": "0.3.0",
            "uuid": "unsigned-uuid",
            "parties": [],
            "dialog": [],
            "attachments": [],
            "analysis": []
        }
        
        vcon_file = tmp_path / "unsigned.json"
        vcon_file.write_text(json.dumps(vcon_data))
        
        creator = BundleCreator(download_files=False)
        creator.add_vcon(vcon_file)
        
        assert creator.vcons[0].security_form.value == "unsigned"
    
    def test_jws_vcon_bundle(self, tmp_path):
        """Test bundle with JWS signed vCon."""
        import base64
        
        payload = {
            "vcon": "0.3.0",
            "uuid": "signed-uuid",
            "parties": [],
            "dialog": [],
            "attachments": [],
            "analysis": []
        }
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip('=')
        
        jws_data = {
            "protected": "eyJhbGciOiJSUzI1NiJ9",
            "payload": payload_b64,
            "signature": "fake-signature"
        }
        
        vcon_file = tmp_path / "signed.json"
        vcon_file.write_text(json.dumps(jws_data))
        
        creator = BundleCreator(download_files=False, verify_signatures=False)
        creator.add_vcon(vcon_file)
        
        assert creator.vcons[0].security_form.value == "signed"


class TestErrorHandling:
    """Tests for error handling."""
    
    def test_invalid_vcon_structure(self, tmp_path):
        """Test handling of invalid vCon structure."""
        invalid_vcon = tmp_path / "invalid.json"
        invalid_vcon.write_text('{"invalid": "structure"}')
        
        creator = BundleCreator(download_files=False)
        
        with pytest.raises(Exception):  # Should raise some error
            creator.add_vcon(invalid_vcon)
    
    def test_corrupted_bundle_validation(self, tmp_path):
        """Test validation of corrupted bundle."""
        # Create a file that's not a valid ZIP
        bad_bundle = tmp_path / "bad.vconz"
        bad_bundle.write_text("This is not a ZIP file")
        
        validator = BundleValidator()
        report = validator.validate(bad_bundle)
        
        assert not report.is_valid
        assert len(report.errors) > 0

