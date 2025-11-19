"""
Core bundle operations for creating and extracting vCon Zip Bundles.

Provides:
- BundleCreator: Create .vconz bundles from vCon files
- BundleExtractor: Extract and read .vconz bundles
"""

import json
import zipfile
from pathlib import Path
from typing import List, Dict, Optional, Set, Any
from dataclasses import dataclass

from .vcon_parser import VConParser, ParsedVCon, SecurityForm
from .file_resolver import FileResolver
from .manifest import Manifest
from .hash_utils import get_primary_hash


class BundleError(Exception):
    """Base exception for bundle operations."""
    pass


@dataclass
class BundledFile:
    """Represents a file bundled in a vCon Zip Bundle."""
    filename: str
    data: bytes
    content_hash: str


class BundleCreator:
    """
    Creates vCon Zip Bundles from vCon files.
    
    Features:
    - Multi-vCon support with automatic deduplication
    - External file resolution and verification
    - Preservation of all security forms (unsigned, JWS, JWE)
    """
    
    def __init__(
        self,
        verify_signatures: bool = False,
        decryption_key: Optional[Any] = None,
        download_files: bool = True
    ):
        """
        Initialize bundle creator.
        
        Args:
            verify_signatures: Whether to verify JWS signatures
            decryption_key: Optional key for decrypting JWE vCons
            download_files: Whether to download external files
        """
        self.verify_signatures = verify_signatures
        self.decryption_key = decryption_key
        self.download_files = download_files
        
        self.vcons: List[ParsedVCon] = []
        self.files: Dict[str, BundledFile] = {}  # Key: filename, Value: BundledFile
        self.parser = VConParser(decryption_key=decryption_key)
    
    def add_vcon(self, vcon_path: Path) -> None:
        """
        Add a vCon to the bundle.
        
        Args:
            vcon_path: Path to vCon JSON file
            
        Raises:
            BundleError: If vCon cannot be added
        """
        try:
            vcon_content = vcon_path.read_text()
        except Exception as e:
            raise BundleError(f"Failed to read vCon file {vcon_path}: {e}")
        
        try:
            parsed_vcon = self.parser.parse(vcon_content)
        except Exception as e:
            raise BundleError(f"Failed to parse vCon {vcon_path}: {e}")
        
        # Check for duplicate UUID
        for existing in self.vcons:
            if existing.uuid == parsed_vcon.uuid:
                raise BundleError(f"Duplicate vCon UUID: {parsed_vcon.uuid}")
        
        self.vcons.append(parsed_vcon)
        
        # Resolve external files if enabled
        if self.download_files and parsed_vcon.external_references:
            self._resolve_external_files(parsed_vcon)
    
    def add_vcon_from_string(self, vcon_content: str) -> None:
        """
        Add a vCon from string content.
        
        Args:
            vcon_content: vCon JSON string
            
        Raises:
            BundleError: If vCon cannot be added
        """
        try:
            parsed_vcon = self.parser.parse(vcon_content)
        except Exception as e:
            raise BundleError(f"Failed to parse vCon: {e}")
        
        # Check for duplicate UUID
        for existing in self.vcons:
            if existing.uuid == parsed_vcon.uuid:
                raise BundleError(f"Duplicate vCon UUID: {parsed_vcon.uuid}")
        
        self.vcons.append(parsed_vcon)
        
        # Resolve external files if enabled
        if self.download_files and parsed_vcon.external_references:
            self._resolve_external_files(parsed_vcon)
    
    def _resolve_external_files(self, parsed_vcon: ParsedVCon) -> None:
        """
        Resolve and download external files for a vCon.
        
        Args:
            parsed_vcon: Parsed vCon with external references
        """
        with FileResolver() as resolver:
            for ref in parsed_vcon.external_references:
                try:
                    # Download and verify file
                    data, filename = resolver.download_file(ref.url, ref.content_hash)
                    
                    # Get primary hash for deduplication
                    primary_hash = get_primary_hash(ref.content_hash)
                    
                    # Store file (automatically deduplicated by filename)
                    if filename not in self.files:
                        self.files[filename] = BundledFile(
                            filename=filename,
                            data=data,
                            content_hash=primary_hash
                        )
                except Exception as e:
                    raise BundleError(
                        f"Failed to resolve file {ref.url} for vCon {parsed_vcon.uuid}: {e}"
                    )
    
    def create(self, output_path: Path) -> None:
        """
        Create the vCon Zip Bundle.
        
        Args:
            output_path: Path for output .vconz file
            
        Raises:
            BundleError: If bundle creation fails
        """
        if not self.vcons:
            raise BundleError("No vCons added to bundle")
        
        # Validate UUIDs are unique
        self._validate_uuid_uniqueness()
        
        try:
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                # Write manifest.json
                manifest = Manifest()
                zf.writestr('manifest.json', manifest.to_json())
                
                # Write vCons
                for vcon in self.vcons:
                    vcon_filename = f"vcons/{vcon.uuid}.json"
                    zf.writestr(vcon_filename, vcon.original_content)
                
                # Write files
                for bundled_file in self.files.values():
                    file_path = f"files/{bundled_file.filename}"
                    zf.writestr(file_path, bundled_file.data)
        
        except Exception as e:
            raise BundleError(f"Failed to create bundle: {e}")
    
    def _validate_uuid_uniqueness(self) -> None:
        """
        Validate that all vCon UUIDs are unique.
        
        Raises:
            BundleError: If duplicate UUIDs are found
        """
        uuids = [vcon.uuid for vcon in self.vcons]
        if len(uuids) != len(set(uuids)):
            duplicates = [uuid for uuid in uuids if uuids.count(uuid) > 1]
            raise BundleError(f"Duplicate vCon UUIDs found: {set(duplicates)}")


class BundleExtractor:
    """
    Extracts and reads vCon Zip Bundles.
    
    Features:
    - Bundle structure validation
    - File lookup by content hash
    - vCon relationship discovery
    """
    
    def __init__(self, bundle_path: Path):
        """
        Initialize bundle extractor.
        
        Args:
            bundle_path: Path to .vconz bundle file
            
        Raises:
            BundleError: If bundle cannot be opened
        """
        if not bundle_path.exists():
            raise BundleError(f"Bundle file not found: {bundle_path}")
        
        try:
            self.zipfile = zipfile.ZipFile(bundle_path, 'r')
        except zipfile.BadZipFile:
            raise BundleError(f"Invalid ZIP file: {bundle_path}")
        
        self.bundle_path = bundle_path
        self._manifest: Optional[Manifest] = None
        self._vcons_cache: Optional[List[Dict[str, Any]]] = None
    
    def validate_structure(self) -> None:
        """
        Validate bundle structure.
        
        Raises:
            BundleError: If structure is invalid
        """
        namelist = self.zipfile.namelist()
        
        # Check for manifest.json
        if 'manifest.json' not in namelist:
            raise BundleError("Missing manifest.json")
        
        # Check for vcons directory
        has_vcons = any(name.startswith('vcons/') for name in namelist)
        if not has_vcons:
            raise BundleError("Missing vcons/ directory")
        
        # Validate manifest
        try:
            manifest = self.get_manifest()
            if not manifest.is_version_supported():
                raise BundleError(f"Unsupported bundle version: {manifest.version}")
        except Exception as e:
            raise BundleError(f"Invalid manifest: {e}")
    
    def get_manifest(self) -> Manifest:
        """
        Get bundle manifest.
        
        Returns:
            Manifest object
            
        Raises:
            BundleError: If manifest cannot be loaded
        """
        if self._manifest is None:
            try:
                manifest_data = self.zipfile.read('manifest.json').decode('utf-8')
                self._manifest = Manifest.from_json(manifest_data)
            except Exception as e:
                raise BundleError(f"Failed to load manifest: {e}")
        
        return self._manifest
    
    def get_vcons(self) -> List[Dict[str, Any]]:
        """
        Get list of all vCons in bundle.
        
        Returns:
            List of vCon metadata dictionaries with keys: uuid, filename, content
            
        Raises:
            BundleError: If vCons cannot be read
        """
        if self._vcons_cache is not None:
            return self._vcons_cache
        
        vcons = []
        for name in self.zipfile.namelist():
            if name.startswith('vcons/') and name.endswith('.json'):
                try:
                    content = self.zipfile.read(name).decode('utf-8')
                    # Extract UUID from filename
                    filename = Path(name).name
                    uuid = filename.replace('.json', '')
                    
                    vcons.append({
                        'uuid': uuid,
                        'filename': name,
                        'content': content
                    })
                except Exception as e:
                    raise BundleError(f"Failed to read vCon {name}: {e}")
        
        self._vcons_cache = vcons
        return vcons
    
    def get_vcon_by_uuid(self, uuid: str) -> Optional[str]:
        """
        Get vCon content by UUID.
        
        Args:
            uuid: vCon UUID
            
        Returns:
            vCon JSON string or None if not found
        """
        filename = f"vcons/{uuid}.json"
        try:
            return self.zipfile.read(filename).decode('utf-8')
        except KeyError:
            return None
    
    def resolve_file(self, content_hash: str) -> Optional[bytes]:
        """
        Resolve a file by its content hash.
        
        Args:
            content_hash: Content hash to look up
            
        Returns:
            File data or None if not found
        """
        # Look for file in files/ directory with matching hash prefix
        for name in self.zipfile.namelist():
            if name.startswith('files/'):
                filename = Path(name).name
                # Check if filename starts with the content hash
                if filename.startswith(content_hash):
                    return self.zipfile.read(name)
        
        return None
    
    def extract(self, output_dir: Path) -> None:
        """
        Extract entire bundle to directory.
        
        Args:
            output_dir: Directory to extract to
            
        Raises:
            BundleError: If extraction fails
        """
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            self.zipfile.extractall(output_dir)
        except Exception as e:
            raise BundleError(f"Failed to extract bundle: {e}")
    
    def build_relationships(self) -> Dict[str, List[str]]:
        """
        Build relationship graph of vCons based on group[] references.
        
        Returns:
            Dictionary mapping vCon UUID to list of referenced vCon UUIDs
            
        Raises:
            BundleError: If relationships cannot be parsed
        """
        relationships = {}
        
        for vcon_info in self.get_vcons():
            try:
                vcon_data = json.loads(vcon_info['content'])
                parser = VConParser()
                parsed = parser.parse(vcon_info['content'])
                
                # Extract group references
                referenced_uuids = []
                for item in parsed.vcon_data.get('group', []):
                    if 'uuid' in item:
                        referenced_uuids.append(item['uuid'])
                
                relationships[parsed.uuid] = referenced_uuids
            except Exception as e:
                raise BundleError(
                    f"Failed to parse relationships for {vcon_info['uuid']}: {e}"
                )
        
        return relationships
    
    def close(self) -> None:
        """Close the ZIP file."""
        self.zipfile.close()
    
    def __enter__(self):
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()

