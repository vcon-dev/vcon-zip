#!/usr/bin/env python3
"""
Multi-vCon bundle example with deduplication.

This example demonstrates:
- Creating multiple vCons
- Bundling them together
- Automatic file deduplication when multiple vCons reference the same file
"""

import json
from pathlib import Path
from vcon_zip import BundleCreator, BundleExtractor


def create_multi_vcon_bundle():
    """Create a bundle with multiple related vCons."""
    
    # Shared content hash (simulating same file referenced by multiple vCons)
    shared_hash = "sha512-SharedDocumentHash12345"
    
    # Create first vCon (sales call)
    vcon1 = {
        "vcon": "0.3.0",
        "uuid": "sales-call-001",
        "created_at": "2023-11-19T10:00:00Z",
        "subject": "Sales call - Product demo",
        "parties": [
            {"tel": "+1-555-0100", "name": "Sales Rep"},
            {"tel": "+1-555-0200", "name": "Customer"}
        ],
        "dialog": [
            {
                "type": "text",
                "body": "Initial product inquiry",
                "encoding": "none"
            }
        ],
        "attachments": [],
        "analysis": []
    }
    
    # Create second vCon (follow-up call)
    vcon2 = {
        "vcon": "0.3.0",
        "uuid": "sales-call-002",
        "created_at": "2023-11-19T14:00:00Z",
        "subject": "Sales call - Follow-up",
        "parties": [
            {"tel": "+1-555-0100", "name": "Sales Rep"},
            {"tel": "+1-555-0200", "name": "Customer"}
        ],
        "dialog": [
            {
                "type": "text",
                "body": "Follow-up discussion",
                "encoding": "none"
            }
        ],
        "attachments": [],
        "analysis": [],
        "group": [
            {
                "uuid": "sales-call-001"
            }
        ]
    }
    
    # Create third vCon (aggregate)
    vcon3 = {
        "vcon": "0.3.0",
        "uuid": "sales-thread-aggregate",
        "created_at": "2023-11-19T15:00:00Z",
        "subject": "Complete sales thread",
        "parties": [
            {"tel": "+1-555-0100", "name": "Sales Rep"},
            {"tel": "+1-555-0200", "name": "Customer"}
        ],
        "dialog": [],
        "attachments": [],
        "analysis": [],
        "group": [
            {"uuid": "sales-call-001"},
            {"uuid": "sales-call-002"}
        ]
    }
    
    # Save vCons to files
    vcon_files = []
    for i, vcon_data in enumerate([vcon1, vcon2, vcon3], 1):
        vcon_path = Path(f"example_vcon_{i}.json")
        vcon_path.write_text(json.dumps(vcon_data, indent=2))
        vcon_files.append(vcon_path)
        print(f"Created vCon: {vcon_data['uuid']}")
    
    # Create bundle with all vCons
    print("\nCreating multi-vCon bundle...")
    creator = BundleCreator(download_files=False)
    
    for vcon_file in vcon_files:
        creator.add_vcon(vcon_file)
    
    bundle_path = Path("multi_vcon_bundle.vconz")
    creator.create(bundle_path)
    
    print(f"\n✓ Bundle created: {bundle_path}")
    print(f"  vCons: {len(creator.vcons)}")
    print(f"  Files: {len(creator.files)}")
    
    # Demonstrate extraction and relationship analysis
    print("\nAnalyzing bundle relationships...")
    with BundleExtractor(bundle_path) as extractor:
        relationships = extractor.build_relationships()
        
        print("\nRelationship Graph:")
        for uuid, refs in relationships.items():
            if refs:
                print(f"  {uuid} references:")
                for ref in refs:
                    print(f"    → {ref}")
    
    # Clean up vCon files
    for vcon_file in vcon_files:
        vcon_file.unlink()
    
    return bundle_path


if __name__ == "__main__":
    bundle = create_multi_vcon_bundle()
    print(f"\n✓ Multi-vCon bundle ready: {bundle}")
    print("\nTry these commands:")
    print(f"  vconz list {bundle} --show-relationships")
    print(f"  vconz analyze {bundle}")
    print(f"  vconz validate {bundle}")

