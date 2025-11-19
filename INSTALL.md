# Installation Guide

## Prerequisites

- Python 3.12 or higher
- pip package manager

## Installation Methods

### Method 1: Virtual Environment (Recommended)

Create a virtual environment to avoid system package conflicts:

```bash
# Navigate to project directory
cd /Users/thomashowe/Documents/GitHub/vcon-zip

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate  # On macOS/Linux
# OR
venv\Scripts\activate  # On Windows

# Install the package
pip install -e .

# Verify installation
vconz --version
```

### Method 2: Install with Development Dependencies

If you want to run tests and contribute to development:

```bash
# Activate virtual environment first
source venv/bin/activate

# Install with development dependencies
pip install -e ".[dev]"

# Run tests to verify
pytest
```

### Method 3: User Installation

Install to your user directory without affecting system Python:

```bash
pip install --user -e .
```

## Verify Installation

After installation, verify everything works:

```bash
# Check CLI is available
vconz --version

# Should output: vconz, version 1.0.0

# Check Python import works
python3 -c "from vcon_zip import BundleCreator; print('✓ Import successful')"
```

## Dependencies

The following packages will be installed automatically:

### Required Dependencies
- python-jose[cryptography] >= 3.3.0
- cryptography >= 41.0.0
- requests >= 2.31.0
- click >= 8.1.0

### Development Dependencies (optional)
- pytest >= 7.4.0
- pytest-cov >= 4.1.0
- pytest-mock >= 3.11.0
- black >= 23.7.0
- mypy >= 1.5.0
- ruff >= 0.0.285

## Quick Start After Installation

Try the examples:

```bash
# Run simple example
python3 examples/simple_bundle.py

# Run multi-vCon example
python3 examples/multi_vcon_bundle.py

# Run validation example
python3 examples/validation_example.py
```

## Troubleshooting

### Issue: "No module named 'jose'"

**Solution**: The dependencies aren't installed. Install the package properly:
```bash
pip install -e .
```

### Issue: "externally-managed-environment" error

**Solution**: Use a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Issue: "vconz command not found"

**Solution**: Either:
1. Activate the virtual environment where you installed it
2. Add the installation directory to your PATH
3. Use the full path to the command
4. Use `python3 -m vcon_zip.cli` instead

### Issue: Tests fail to run

**Solution**: Install development dependencies:
```bash
pip install -e ".[dev]"
```

## Uninstallation

To uninstall:

```bash
pip uninstall vcon-zip
```

## Next Steps

1. Read the [README.md](README.md) for usage examples
2. Try the example scripts in `examples/`
3. Run the test suite: `pytest`
4. Check the [IMPLEMENTATION_SUMMARY.md](IMPLEMENTATION_SUMMARY.md) for details

## Support

For issues or questions:
- Check existing documentation
- Run tests to verify installation: `pytest -v`
- Check Python version: `python3 --version` (must be 3.12+)

