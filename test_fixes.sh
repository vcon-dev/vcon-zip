#!/bin/bash
# Quick test script to verify the fixes

cd /Users/thomashowe/Documents/GitHub/vcon-zip

# Activate virtual environment if it exists
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

echo "Testing the two fixed tests..."
echo ""

# Run the specific tests that were fixed
pytest tests/test_cli.py::TestCLI::test_main_no_args \
       tests/test_file_resolver.py::TestFileResolver::test_determine_extension_from_magic_bytes \
       -v

echo ""
echo "Running all tests to verify nothing broke..."
echo ""

# Run all tests
pytest --tb=short

echo ""
echo "Done!"

