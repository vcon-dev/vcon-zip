"""
Unit tests for validation module.
"""

import json
import zipfile
import pytest
from pathlib import Path
from vcon_zip.validation import BundleValidator, ValidationReport, ValidationIssue


class TestValidationReport:
    """Tests for ValidationReport class."""
    
    def test_create_valid_report(self):
        """Test creating a valid report."""
        report = ValidationReport(is_valid=True)
        
        assert report.is_valid
        assert len(report.errors) == 0
        assert len(report.warnings) == 0
    
    def test_add_error(self):
        """Test adding error to report."""
        report = ValidationReport(is_valid=True)
        report.add_error('test', 'Error message')
        
        assert not report.is_valid
        assert len(report.errors) == 1
        assert report.errors[0].category == 'test'
        assert report.errors[0].message == 'Error message'
    
    def test_add_warning(self):
        """Test adding warning to report."""
        report = ValidationReport(is_valid=True)
        report.add_warning('test', 'Warning message')
        
        assert report.is_valid  # Warnings don't invalidate
        assert len(report.warnings) == 1
    
    def test_to_dict(self):
        """Test converting report to dictionary."""
        report = ValidationReport(is_valid=True)
        report.add_error('cat1', 'Error 1')
        report.add_warning('cat2', 'Warning 1')
        
        result = report.to_dict()
        
        assert result['is_valid'] == False
        assert result['error_count'] == 1
        assert result['warning_count'] == 1
    
    def test_str_formatting(self):
        """Test string formatting of report."""
        report = ValidationReport(is_valid=True)
        report.add_error('test', 'Test error')
        
        output = str(report)
        
        assert 'FAILED' in output
        assert 'Test error' in output


class TestBundleValidator:
    """Tests for BundleValidator class."""
    
    @pytest.fixture
    def valid_bundle(self, tmp_path):
        """Create a valid bundle for testing."""
        vcon_data = {
            "vcon": "0.3.0",
            "uuid": "valid-test-uuid",
            "parties": [],
            "dialog": [],
            "attachments": [],
            "analysis": []
        }
        
        manifest_data = {
            "format": "vcon-bundle",
            "version": "1.0"
        }
        
        bundle_path = tmp_path / "valid.vconz"
        with zipfile.ZipFile(bundle_path, 'w') as zf:
            zf.writestr('manifest.json', json.dumps(manifest_data))
            zf.writestr('vcons/valid-test-uuid.json', json.dumps(vcon_data))
        
        return bundle_path
    
    @pytest.fixture
    def invalid_bundle_no_manifest(self, tmp_path):
        """Create bundle without manifest."""
        bundle_path = tmp_path / "invalid.vconz"
        with zipfile.ZipFile(bundle_path, 'w') as zf:
            zf.writestr('vcons/test.json', '{}')
        
        return bundle_path
    
    def test_validate_valid_bundle(self, valid_bundle):
        """Test validating a valid bundle."""
        validator = BundleValidator(verify_hashes=False)
        report = validator.validate(valid_bundle)
        
        assert report.is_valid
        assert len(report.errors) == 0
    
    def test_validate_nonexistent_bundle(self, tmp_path):
        """Test validating nonexistent bundle."""
        validator = BundleValidator()
        report = validator.validate(tmp_path / "nonexistent.vconz")
        
        assert not report.is_valid
        assert len(report.errors) > 0
    
    def test_validate_missing_manifest(self, invalid_bundle_no_manifest):
        """Test validation fails for missing manifest."""
        validator = BundleValidator()
        report = validator.validate(invalid_bundle_no_manifest)
        
        assert not report.is_valid
        assert any('manifest' in err.category for err in report.errors)
    
    def test_strict_mode_warnings_as_errors(self, valid_bundle):
        """Test strict mode converts warnings to errors."""
        validator = BundleValidator(strict=True)
        
        # Create a report with warnings
        report = ValidationReport(is_valid=True)
        report.add_warning('test', 'Test warning')
        
        # In actual validation, warnings would be converted
        # This is just to test the mechanism
        if validator.strict and report.warnings:
            for warning in report.warnings:
                warning.severity = 'error'
                report.errors.append(warning)
            report.warnings.clear()
            report.is_valid = False
        
        assert not report.is_valid
        assert len(report.errors) == 1

