"""
Command-line interface for vCon Zip Bundle operations.

Provides commands for:
- Creating bundles from vCon files
- Extracting bundles
- Validating bundles
- Listing bundle contents
- Analyzing bundle relationships
"""

import sys
import json
from pathlib import Path
from typing import Optional

import click

from .bundle import BundleCreator, BundleExtractor, BundleError
from .validation import BundleValidator
from .vcon_parser import VConParser
from .security import KeyManager


@click.group()
@click.version_option(version='1.0.0')
def main():
    """vCon Zip Bundle - Package and manage vCon conversation containers."""
    pass


@main.command()
@click.argument('vcon_files', nargs=-1, type=click.Path(exists=True), required=True)
@click.option('-o', '--output', required=True, type=click.Path(), help='Output .vconz file path')
@click.option('--verify-signatures', is_flag=True, help='Verify JWS signatures')
@click.option('--decrypt-key', type=click.Path(exists=True), help='Private key for JWE decryption')
@click.option('--no-download', is_flag=True, help='Skip external file downloads')
def create(vcon_files, output, verify_signatures, decrypt_key, no_download):
    """Create a vCon Zip Bundle from vCon files."""
    try:
        # Load decryption key if provided
        decryption_key = None
        if decrypt_key:
            try:
                decryption_key = KeyManager.load_key_from_file(decrypt_key)
                click.echo(f"Loaded decryption key from {decrypt_key}")
            except Exception as e:
                click.echo(f"Error loading decryption key: {e}", err=True)
                sys.exit(1)
        
        # Create bundle
        creator = BundleCreator(
            verify_signatures=verify_signatures,
            decryption_key=decryption_key,
            download_files=not no_download
        )
        
        # Add vCon files
        click.echo(f"Adding {len(vcon_files)} vCon(s)...")
        for vcon_file in vcon_files:
            vcon_path = Path(vcon_file)
            click.echo(f"  Adding {vcon_path.name}...")
            try:
                creator.add_vcon(vcon_path)
            except Exception as e:
                click.echo(f"  Error: {e}", err=True)
                sys.exit(1)
        
        # Create bundle
        output_path = Path(output)
        click.echo(f"Creating bundle at {output_path}...")
        creator.create(output_path)
        
        # Report statistics
        num_vcons = len(creator.vcons)
        num_files = len(creator.files)
        click.echo(f"✓ Bundle created successfully")
        click.echo(f"  vCons: {num_vcons}")
        click.echo(f"  Files: {num_files}")
        
    except BundleError as e:
        click.echo(f"Error creating bundle: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('bundle', type=click.Path(exists=True))
@click.option('-d', '--directory', required=True, type=click.Path(), help='Output directory')
@click.option('--verify', is_flag=True, help='Verify all hashes during extraction')
def extract(bundle, directory, verify):
    """Extract a vCon Zip Bundle."""
    try:
        bundle_path = Path(bundle)
        output_dir = Path(directory)
        
        click.echo(f"Extracting {bundle_path.name}...")
        
        with BundleExtractor(bundle_path) as extractor:
            # Validate if requested
            if verify:
                click.echo("Validating bundle...")
                validator = BundleValidator(verify_hashes=True)
                report = validator.validate(bundle_path)
                
                if not report.is_valid:
                    click.echo("Validation failed:", err=True)
                    click.echo(str(report), err=True)
                    sys.exit(1)
                
                click.echo("✓ Validation passed")
            
            # Extract
            extractor.extract(output_dir)
            
            # Report statistics
            vcons = extractor.get_vcons()
            click.echo(f"✓ Extracted successfully to {output_dir}")
            click.echo(f"  vCons: {len(vcons)}")
        
    except BundleError as e:
        click.echo(f"Error extracting bundle: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('bundle', type=click.Path(exists=True))
@click.option('--verbose', is_flag=True, help='Show detailed validation report')
def validate(bundle, verbose):
    """Validate a vCon Zip Bundle."""
    try:
        bundle_path = Path(bundle)
        
        click.echo(f"Validating {bundle_path.name}...")
        
        validator = BundleValidator(verify_hashes=True)
        report = validator.validate(bundle_path)
        
        if report.is_valid:
            click.echo("✓ Bundle is valid")
            if verbose and report.warnings:
                click.echo(f"\nWarnings: {len(report.warnings)}")
                for warning in report.warnings:
                    click.echo(f"  [{warning.category}] {warning.message}")
            sys.exit(0)
        else:
            click.echo("✗ Bundle validation failed", err=True)
            if verbose or True:  # Always show errors
                click.echo(str(report))
            sys.exit(1)
        
    except Exception as e:
        click.echo(f"Error validating bundle: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('bundle', type=click.Path(exists=True))
@click.option('--show-relationships', is_flag=True, help='Display group references')
def list(bundle, show_relationships):
    """List vCons and files in a bundle."""
    try:
        bundle_path = Path(bundle)
        
        with BundleExtractor(bundle_path) as extractor:
            # List vCons
            vcons = extractor.get_vcons()
            click.echo(f"vCons ({len(vcons)}):")
            for vcon in vcons:
                click.echo(f"  {vcon['uuid']}")
            
            # List files
            file_names = [
                Path(name).name for name in extractor.zipfile.namelist()
                if name.startswith('files/') and not name.endswith('/')
            ]
            
            click.echo(f"\nFiles ({len(file_names)}):")
            for filename in file_names[:10]:  # Show first 10
                click.echo(f"  {filename}")
            
            if len(file_names) > 10:
                click.echo(f"  ... and {len(file_names) - 10} more")
            
            # Show relationships if requested
            if show_relationships:
                click.echo("\nRelationships:")
                relationships = extractor.build_relationships()
                for uuid, refs in relationships.items():
                    if refs:
                        click.echo(f"  {uuid} -> {', '.join(refs)}")
        
    except BundleError as e:
        click.echo(f"Error reading bundle: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('bundle', type=click.Path(exists=True))
def info(bundle):
    """Show bundle metadata and statistics."""
    try:
        bundle_path = Path(bundle)
        
        with BundleExtractor(bundle_path) as extractor:
            # Get manifest
            manifest = extractor.get_manifest()
            
            # Get vCons
            vcons = extractor.get_vcons()
            
            # Count files
            file_names = [
                name for name in extractor.zipfile.namelist()
                if name.startswith('files/') and not name.endswith('/')
            ]
            
            # Calculate total size
            total_size = sum(
                extractor.zipfile.getinfo(name).file_size
                for name in extractor.zipfile.namelist()
            )
            
            click.echo(f"Bundle: {bundle_path.name}")
            click.echo(f"Format: {manifest.format}")
            click.echo(f"Version: {manifest.version}")
            click.echo(f"vCons: {len(vcons)}")
            click.echo(f"Files: {len(file_names)}")
            click.echo(f"Total size: {total_size:,} bytes ({total_size / 1024 / 1024:.2f} MB)")
        
    except BundleError as e:
        click.echo(f"Error reading bundle: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


@main.command()
@click.argument('bundle', type=click.Path(exists=True))
def analyze(bundle):
    """Analyze bundle relationships and statistics."""
    try:
        bundle_path = Path(bundle)
        
        with BundleExtractor(bundle_path) as extractor:
            # Parse all vCons
            vcons = extractor.get_vcons()
            parser = VConParser()
            
            stats = {
                'total_vcons': len(vcons),
                'security_forms': {'unsigned': 0, 'signed': 0, 'encrypted': 0},
                'total_external_refs': 0,
                'ref_types': {'dialog': 0, 'attachment': 0, 'analysis': 0, 'group': 0},
                'with_groups': 0
            }
            
            for vcon_info in vcons:
                try:
                    parsed = parser.parse(vcon_info['content'])
                    
                    # Count security forms
                    stats['security_forms'][parsed.security_form.value] += 1
                    
                    # Count references
                    stats['total_external_refs'] += len(parsed.external_references)
                    
                    for ref in parsed.external_references:
                        stats['ref_types'][ref.reference_type] += 1
                    
                    # Check for group references
                    if parsed.vcon_data.get('group'):
                        stats['with_groups'] += 1
                
                except Exception as e:
                    click.echo(f"Warning: Could not parse {vcon_info['uuid']}: {e}", err=True)
            
            # Get relationships
            relationships = extractor.build_relationships()
            
            # Display statistics
            click.echo(f"Bundle Analysis: {bundle_path.name}")
            click.echo(f"\nvCons: {stats['total_vcons']}")
            click.echo(f"  Unsigned: {stats['security_forms']['unsigned']}")
            click.echo(f"  Signed: {stats['security_forms']['signed']}")
            click.echo(f"  Encrypted: {stats['security_forms']['encrypted']}")
            
            click.echo(f"\nExternal References: {stats['total_external_refs']}")
            click.echo(f"  Dialog: {stats['ref_types']['dialog']}")
            click.echo(f"  Attachments: {stats['ref_types']['attachment']}")
            click.echo(f"  Analysis: {stats['ref_types']['analysis']}")
            click.echo(f"  Group: {stats['ref_types']['group']}")
            
            click.echo(f"\nRelationships:")
            click.echo(f"  vCons with group references: {stats['with_groups']}")
            
            # Show relationship graph
            if any(refs for refs in relationships.values()):
                click.echo(f"  Relationship graph:")
                for uuid, refs in relationships.items():
                    if refs:
                        click.echo(f"    {uuid[:8]}... -> {len(refs)} vCon(s)")
        
    except BundleError as e:
        click.echo(f"Error analyzing bundle: {e}", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"Unexpected error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()

