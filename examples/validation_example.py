#!/usr/bin/env python3
"""
Bundle validation example.

Demonstrates comprehensive validation of vCon Zip Bundles including:
- Structure validation
- Hash verification
- Reference checking
- Error reporting
"""

import json
from pathlib import Path
from vcon_zip import BundleCreator, BundleValidator


def create_and_validate_bundle():
    """Create a bundle and demonstrate validation."""
    
    # Create a valid vCon
    vcon_data = {
        "vcon": "0.3.0",
        "uuid": "validation-example-uuid",
        "created_at": "2023-11-19T12:00:00Z",
        "subject": "Validation example",
        "parties": [
            {"tel": "+1-555-0300", "name": "Charlie"}
        ],
        "dialog": [
            {
                "type": "text",
                "body": "Example dialog content",
                "encoding": "none"
            }
        ],
        "attachments": [],
        "analysis": []
    }
    
    # Save and bundle
    vcon_path = Path("validation_example.json")
    vcon_path.write_text(json.dumps(vcon_data, indent=2))
    
    print("Creating bundle...")
    creator = BundleCreator(download_files=False)
    creator.add_vcon(vcon_path)
    
    bundle_path = Path("validation_example.vconz")
    creator.create(bundle_path)
    print(f"✓ Bundle created: {bundle_path}")
    
    # Validate bundle
    print("\nValidating bundle...")
    validator = BundleValidator(verify_hashes=True, strict=False)
    report = validator.validate(bundle_path)
    
    # Display results
    print("\n" + "=" * 60)
    print("VALIDATION REPORT")
    print("=" * 60)
    
    if report.is_valid:
        print("✓ Bundle is VALID")
    else:
        print("✗ Bundle is INVALID")
    
    print(f"\nErrors: {len(report.errors)}")
    for error in report.errors:
        print(f"  [{error.category}] {error.message}")
        if error.details:
            for key, value in error.details.items():
                print(f"    {key}: {value}")
    
    print(f"\nWarnings: {len(report.warnings)}")
    for warning in report.warnings:
        print(f"  [{warning.category}] {warning.message}")
        if warning.details:
            for key, value in warning.details.items():
                print(f"    {key}: {value}")
    
    # Get detailed report as dictionary
    report_dict = report.to_dict()
    print("\nReport summary:")
    print(f"  Valid: {report_dict['is_valid']}")
    print(f"  Error count: {report_dict['error_count']}")
    print(f"  Warning count: {report_dict['warning_count']}")
    
    # Demonstrate strict mode
    print("\n" + "=" * 60)
    print("STRICT MODE VALIDATION")
    print("=" * 60)
    
    strict_validator = BundleValidator(verify_hashes=True, strict=True)
    strict_report = strict_validator.validate(bundle_path)
    
    print(f"Strict mode result: {'VALID' if strict_report.is_valid else 'INVALID'}")
    print("(In strict mode, warnings are treated as errors)")
    
    # Clean up
    vcon_path.unlink()
    
    return bundle_path, report


if __name__ == "__main__":
    bundle, report = create_and_validate_bundle()
    
    print("\n" + "=" * 60)
    print("PROGRAMMATIC VALIDATION")
    print("=" * 60)
    
    # Show how to use validation in code
    if report.is_valid:
        print("✓ Bundle passed validation - safe to process")
        print(f"  You can now work with: {bundle}")
    else:
        print("✗ Bundle failed validation - do not process")
        print("  Fix the following errors:")
        for i, error in enumerate(report.errors, 1):
            print(f"  {i}. {error.message}")

