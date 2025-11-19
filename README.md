# vCon Zip Bundle

Python implementation of the vCon Zip Bundle (.vconz) format for packaging vCon conversation data containers with their associated media files.

## Overview

The vCon Zip Bundle format provides a standardized way to package one or more vCons (conversation data containers) along with their external media files into a single, self-contained ZIP archive.

### Key Features

- **Multi-vCon Support**: Bundle multiple vCons together with automatic file deduplication
- **All Security Forms**: Supports unsigned, JWS signed, and JWE encrypted vCons
- **Content Integrity**: SHA-512/SHA-256 hash verification for all files
- **Offline Processing**: No network dependencies after bundle creation
- **Platform Independence**: Standard ZIP format supported everywhere
- **Simple Structure**: Flat file organization with hash-based naming

## Installation

### From PyPI

```bash
pip install vcon-zip
```

### From Source

```bash
git clone https://github.com/vcon-dev/vcon-zip.git
cd vcon-zip
pip install -e .
```

### With Development Dependencies

```bash
pip install -e ".[dev]"
```

## Requirements

- Python 3.12+
- Dependencies:
  - python-jose[cryptography] - JWS/JWE support
  - cryptography - Cryptographic operations
  - requests - HTTPS downloads
  - click - CLI framework

## Quick Start

### Creating a Bundle

```bash
# Create a bundle from one or more vCon files
vconz create vcon1.json vcon2.json -o my-bundle.vconz

# Create without downloading external files
vconz create vcon.json -o bundle.vconz --no-download

# Create with signature verification
vconz create signed-vcon.json -o bundle.vconz --verify-signatures
```

### Extracting a Bundle

```bash
# Extract bundle to directory
vconz extract my-bundle.vconz -d output-dir

# Extract with hash verification
vconz extract my-bundle.vconz -d output-dir --verify
```

### Validating a Bundle

```bash
# Validate bundle integrity
vconz validate my-bundle.vconz

# Validate with detailed output
vconz validate my-bundle.vconz --verbose
```

### Listing Bundle Contents

```bash
# List vCons and files in bundle
vconz list my-bundle.vconz

# Show vCon relationships
vconz list my-bundle.vconz --show-relationships
```

### Bundle Information

```bash
# Show bundle metadata
vconz info my-bundle.vconz

# Analyze bundle statistics and relationships
vconz analyze my-bundle.vconz
```

## Python API

### Creating Bundles

```python
from pathlib import Path
from vcon_zip import BundleCreator

# Create bundle
creator = BundleCreator(download_files=True)

# Add vCons
creator.add_vcon(Path("vcon1.json"))
creator.add_vcon(Path("vcon2.json"))

# Create the bundle
creator.create(Path("output.vconz"))
```

### Extracting Bundles

```python
from pathlib import Path
from vcon_zip import BundleExtractor

# Open and extract bundle
with BundleExtractor(Path("bundle.vconz")) as extractor:
    # Validate structure
    extractor.validate_structure()
    
    # Get all vCons
    vcons = extractor.get_vcons()
    
    # Get specific vCon by UUID
    vcon_content = extractor.get_vcon_by_uuid("some-uuid")
    
    # Extract to directory
    extractor.extract(Path("output-dir"))
```

### Validating Bundles

```python
from pathlib import Path
from vcon_zip import BundleValidator

# Validate bundle
validator = BundleValidator(verify_hashes=True)
report = validator.validate(Path("bundle.vconz"))

if report.is_valid:
    print("Bundle is valid!")
else:
    print(f"Validation failed with {len(report.errors)} errors")
    for error in report.errors:
        print(f"  - [{error.category}] {error.message}")
```

### Working with Security Forms

```python
from pathlib import Path
from vcon_zip import BundleCreator
from vcon_zip.security import KeyManager

# Load decryption key for JWE vCons
key = KeyManager.load_key_from_file("private_key.pem")

# Create bundle with decryption support
creator = BundleCreator(
    verify_signatures=True,
    decryption_key=key,
    download_files=True
)

creator.add_vcon(Path("encrypted-vcon.json"))
creator.create(Path("bundle.vconz"))
```

## Bundle Structure

```
bundle.vconz (ZIP archive)
├── manifest.json              # Bundle format metadata
├── vcons/                     # All vCon JSON files
│   ├── <uuid-1>.json
│   └── <uuid-2>.json
└── files/                     # All media files (deduplicated)
    ├── sha512-<hash>.wav
    ├── sha512-<hash>.pdf
    └── sha512-<hash>.json
```

## Specification Compliance

This implementation follows the vCon Zip Bundle specification:
- Draft: draft-miller-vcon-zip-bundle-00
- Format version: 1.0
- Full support for all vCon security forms (unsigned, JWS, JWE)
- SHA-512 and SHA-256 content hash verification
- Automatic file deduplication based on content hashes

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=vcon_zip --cov-report=html

# Run specific test file
pytest tests/test_bundle.py

# Run integration tests only
pytest tests/test_integration.py
```

### Code Quality

```bash
# Format code
black src/ tests/

# Lint code
ruff src/ tests/

# Type checking
mypy src/
```

## Examples

See the `examples/` directory for more detailed examples:

- `simple_bundle.py` - Create a basic single-vCon bundle
- `multi_vcon_bundle.py` - Create multi-vCon bundle with deduplication
- `signed_bundle.py` - Work with JWS signed vCons
- `batch_processing.py` - Batch process multiple bundles

## Error Handling

The library provides specific exceptions for different error types:

- `BundleError` - General bundle operation errors
- `VConParserError` - vCon parsing errors
- `HashMismatchError` - Content hash verification failures
- `FileResolverError` - File download/resolution errors
- `NetworkError` - Network operation failures
- `AccessDeniedError` - HTTP 401/403 errors
- `ManifestError` - Manifest validation errors
- `SecurityError` - JWS/JWE operation errors

## Security Considerations

- All downloaded files are verified against their content hashes
- HTTPS is required for all external file references
- JWS signatures are preserved (optional verification)
- JWE encryption is preserved (optional decryption)
- No automatic security downgrade (signed/encrypted stay that way)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see LICENSE file for details

## Authors

Implementation of the vCon Zip Bundle specification by the vCon working group.

## References

- [vCon Specification](https://datatracker.ietf.org/doc/draft-ietf-vcon-vcon-core/)
- [vCon Zip Bundle Specification](https://github.com/vcon-dev/vcon-zip-bundle)
- [IETF vCon Working Group](https://datatracker.ietf.org/wg/vcon/)

## Support

For issues, questions, or contributions:
- GitHub Issues: https://github.com/vcon-dev/vcon-zip/issues
- Documentation: https://github.com/vcon-dev/vcon-zip#readme

