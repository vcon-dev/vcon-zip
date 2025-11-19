"""
Bundle validation for vCon Zip Bundles.

Provides comprehensive validation including:
- Structure validation
- Manifest validation
- vCon integrity checks
- File hash verification
- Reference completeness
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from .bundle import BundleExtractor, BundleError
from .vcon_parser import VConParser
from .hash_utils import verify_content_hash, parse_content_hash


@dataclass
class ValidationIssue:
    """Represents a validation issue."""
    severity: str  # 'error' or 'warning'
    category: str  # e.g., 'structure', 'manifest', 'vcon', 'file', 'reference'
    message: str
    details: Optional[Dict[str, Any]] = None


@dataclass
class ValidationReport:
    """Validation report with errors and warnings."""
    is_valid: bool
    errors: List[ValidationIssue] = field(default_factory=list)
    warnings: List[ValidationIssue] = field(default_factory=list)
    
    def add_error(self, category: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Add an error to the report."""
        self.is_valid = False
        self.errors.append(ValidationIssue('error', category, message, details))
    
    def add_warning(self, category: str, message: str, details: Optional[Dict[str, Any]] = None) -> None:
        """Add a warning to the report."""
        self.warnings.append(ValidationIssue('warning', category, message, details))
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            'is_valid': self.is_valid,
            'error_count': len(self.errors),
            'warning_count': len(self.warnings),
            'errors': [
                {
                    'severity': e.severity,
                    'category': e.category,
                    'message': e.message,
                    'details': e.details
                }
                for e in self.errors
            ],
            'warnings': [
                {
                    'severity': w.severity,
                    'category': w.category,
                    'message': w.message,
                    'details': w.details
                }
                for w in self.warnings
            ]
        }
    
    def __str__(self) -> str:
        """Format report as string."""
        lines = []
        
        if self.is_valid:
            lines.append("Bundle validation: PASSED")
        else:
            lines.append("Bundle validation: FAILED")
        
        if self.errors:
            lines.append(f"\nErrors ({len(self.errors)}):")
            for i, error in enumerate(self.errors, 1):
                lines.append(f"  {i}. [{error.category}] {error.message}")
                if error.details:
                    for key, value in error.details.items():
                        lines.append(f"     {key}: {value}")
        
        if self.warnings:
            lines.append(f"\nWarnings ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings, 1):
                lines.append(f"  {i}. [{warning.category}] {warning.message}")
                if warning.details:
                    for key, value in warning.details.items():
                        lines.append(f"     {key}: {value}")
        
        return '\n'.join(lines)


class BundleValidator:
    """
    Validates vCon Zip Bundles for correctness and integrity.
    
    Performs comprehensive validation including:
    - Bundle structure
    - Manifest format
    - vCon integrity
    - File hash verification
    - Reference completeness
    - UUID uniqueness
    """
    
    def __init__(self, verify_hashes: bool = True, strict: bool = False):
        """
        Initialize validator.
        
        Args:
            verify_hashes: Whether to verify all file content hashes
            strict: Whether to treat warnings as errors
        """
        self.verify_hashes = verify_hashes
        self.strict = strict
    
    def validate(self, bundle_path: Path) -> ValidationReport:
        """
        Validate a vCon Zip Bundle.
        
        Args:
            bundle_path: Path to .vconz bundle
            
        Returns:
            ValidationReport with results
        """
        report = ValidationReport(is_valid=True)
        
        # Try to open bundle
        try:
            extractor = BundleExtractor(bundle_path)
        except BundleError as e:
            report.add_error('structure', f"Cannot open bundle: {e}")
            return report
        
        try:
            # Validate structure
            self._validate_structure(extractor, report)
            
            # Validate manifest
            self._validate_manifest(extractor, report)
            
            # Validate vCons
            self._validate_vcons(extractor, report)
            
            # Validate files
            if self.verify_hashes:
                self._validate_files(extractor, report)
            
            # Check references
            self._check_references(extractor, report)
            
            # Check UUID uniqueness
            self._check_uuid_uniqueness(extractor, report)
        
        finally:
            extractor.close()
        
        # Convert warnings to errors in strict mode
        if self.strict and report.warnings:
            for warning in report.warnings:
                warning.severity = 'error'
                report.errors.append(warning)
            report.warnings.clear()
            report.is_valid = False
        
        return report
    
    def _validate_structure(self, extractor: BundleExtractor, report: ValidationReport) -> None:
        """Validate bundle structure."""
        try:
            extractor.validate_structure()
        except BundleError as e:
            report.add_error('structure', str(e))
    
    def _validate_manifest(self, extractor: BundleExtractor, report: ValidationReport) -> None:
        """Validate manifest.json."""
        try:
            manifest = extractor.get_manifest()
            
            if manifest.format != "vcon-bundle":
                report.add_error('manifest', f"Invalid format: {manifest.format}")
            
            if not manifest.is_version_supported():
                report.add_warning('manifest', f"Version {manifest.version} may not be fully supported")
        
        except Exception as e:
            report.add_error('manifest', f"Manifest validation failed: {e}")
    
    def _validate_vcons(self, extractor: BundleExtractor, report: ValidationReport) -> None:
        """Validate vCon files."""
        try:
            vcons = extractor.get_vcons()
            
            if not vcons:
                report.add_error('vcon', "No vCons found in bundle")
                return
            
            parser = VConParser()
            
            for vcon_info in vcons:
                try:
                    # Parse vCon
                    parsed = parser.parse(vcon_info['content'])
                    
                    # Verify UUID matches filename
                    expected_filename = f"vcons/{parsed.uuid}.json"
                    if vcon_info['filename'] != expected_filename:
                        report.add_error(
                            'vcon',
                            f"vCon filename mismatch",
                            {
                                'expected': expected_filename,
                                'actual': vcon_info['filename']
                            }
                        )
                
                except Exception as e:
                    report.add_error(
                        'vcon',
                        f"Failed to parse vCon {vcon_info['filename']}",
                        {'error': str(e)}
                    )
        
        except Exception as e:
            report.add_error('vcon', f"vCon validation failed: {e}")
    
    def _validate_files(self, extractor: BundleExtractor, report: ValidationReport) -> None:
        """Validate files and verify hashes."""
        try:
            # Get all files in files/ directory
            file_names = [
                name for name in extractor.zipfile.namelist()
                if name.startswith('files/') and not name.endswith('/')
            ]
            
            for file_name in file_names:
                try:
                    # Extract filename and hash
                    filename = Path(file_name).name
                    
                    # Parse hash from filename (format: algorithm-base64url.ext)
                    if '-' not in filename:
                        report.add_warning(
                            'file',
                            f"File has invalid naming format: {filename}"
                        )
                        continue
                    
                    # Extract hash part (before extension)
                    name_without_ext = filename.rsplit('.', 1)[0]
                    
                    # Read file data
                    file_data = extractor.zipfile.read(file_name)
                    
                    # Verify hash
                    try:
                        verify_content_hash(file_data, name_without_ext)
                    except Exception as e:
                        report.add_error(
                            'file',
                            f"Hash verification failed for {filename}",
                            {'error': str(e)}
                        )
                
                except Exception as e:
                    report.add_error(
                        'file',
                        f"Error validating file {file_name}",
                        {'error': str(e)}
                    )
        
        except Exception as e:
            report.add_error('file', f"File validation failed: {e}")
    
    def _check_references(self, extractor: BundleExtractor, report: ValidationReport) -> None:
        """Check that all referenced files exist."""
        try:
            vcons = extractor.get_vcons()
            parser = VConParser()
            
            # Get all file hashes in bundle
            available_files = set()
            for name in extractor.zipfile.namelist():
                if name.startswith('files/'):
                    filename = Path(name).name
                    # Extract hash part (before extension)
                    name_without_ext = filename.rsplit('.', 1)[0] if '.' in filename else filename
                    available_files.add(name_without_ext)
            
            # Check each vCon's references
            for vcon_info in vcons:
                try:
                    parsed = parser.parse(vcon_info['content'])
                    
                    for ref in parsed.external_references:
                        # Get primary hash from reference
                        from .hash_utils import get_primary_hash
                        primary_hash = get_primary_hash(ref.content_hash)
                        
                        # Check if file exists
                        if primary_hash not in available_files:
                            report.add_error(
                                'reference',
                                f"Missing file for reference in vCon {parsed.uuid}",
                                {
                                    'content_hash': primary_hash,
                                    'url': ref.url,
                                    'type': ref.reference_type
                                }
                            )
                
                except Exception as e:
                    report.add_warning(
                        'reference',
                        f"Could not check references for vCon {vcon_info['uuid']}",
                        {'error': str(e)}
                    )
            
            # Check for orphaned files
            referenced_hashes = set()
            for vcon_info in vcons:
                try:
                    parsed = parser.parse(vcon_info['content'])
                    for ref in parsed.external_references:
                        from .hash_utils import get_primary_hash
                        primary_hash = get_primary_hash(ref.content_hash)
                        referenced_hashes.add(primary_hash)
                except:
                    pass
            
            orphaned = available_files - referenced_hashes
            if orphaned:
                report.add_warning(
                    'reference',
                    f"Found {len(orphaned)} file(s) not referenced by any vCon",
                    {'files': list(orphaned)[:5]}  # Show first 5
                )
        
        except Exception as e:
            report.add_error('reference', f"Reference checking failed: {e}")
    
    def _check_uuid_uniqueness(self, extractor: BundleExtractor, report: ValidationReport) -> None:
        """Check that all vCon UUIDs are unique."""
        try:
            vcons = extractor.get_vcons()
            uuids = [v['uuid'] for v in vcons]
            
            # Find duplicates
            seen = set()
            duplicates = set()
            for uuid in uuids:
                if uuid in seen:
                    duplicates.add(uuid)
                seen.add(uuid)
            
            if duplicates:
                report.add_error(
                    'vcon',
                    "Duplicate vCon UUIDs found",
                    {'duplicates': list(duplicates)}
                )
        
        except Exception as e:
            report.add_error('vcon', f"UUID uniqueness check failed: {e}")

