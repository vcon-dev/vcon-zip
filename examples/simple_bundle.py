#!/usr/bin/env python3
"""
Simple example: Create a basic single-vCon bundle.

This example demonstrates creating a bundle from a single vCon file
without downloading external files.
"""

import json
from pathlib import Path
from vcon_zip import BundleCreator


def create_simple_bundle():
    """Create a simple vCon bundle."""
    
    # Create a sample vCon
    vcon_data = {
        "vcon": "0.3.0",
        "uuid": "example-simple-uuid",
        "created_at": "2023-11-19T10:00:00Z",
        "subject": "Example conversation",
        "parties": [
            {"tel": "+1-555-0100", "name": "Alice"},
            {"tel": "+1-555-0200", "name": "Bob"}
        ],
        "dialog": [
            {
                "type": "text",
                "body": "This is an inline text dialog",
                "encoding": "none",
                "start": "2023-11-19T10:00:00Z",
                "parties": [0, 1]
            }
        ],
        "attachments": [],
        "analysis": []
    }
    
    # Save vCon to file
    vcon_path = Path("example_vcon.json")
    vcon_path.write_text(json.dumps(vcon_data, indent=2))
    print(f"Created vCon file: {vcon_path}")
    
    # Create bundle
    creator = BundleCreator(download_files=False)
    creator.add_vcon(vcon_path)
    
    bundle_path = Path("simple_bundle.vconz")
    creator.create(bundle_path)
    
    print(f"✓ Bundle created: {bundle_path}")
    print(f"  vCons: {len(creator.vcons)}")
    print(f"  Files: {len(creator.files)}")
    
    # Clean up
    vcon_path.unlink()
    
    return bundle_path


if __name__ == "__main__":
    bundle = create_simple_bundle()
    print(f"\nBundle ready: {bundle}")
    print("You can now extract it with: vconz extract simple_bundle.vconz -d output")

