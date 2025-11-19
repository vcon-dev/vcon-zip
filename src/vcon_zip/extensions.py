"""
Extension support for vCon Zip Bundles.

Provides functionality for:
- Detecting extensions in vCons
- Bundling extension-specific files
- Extracting extension data
- Managing extension metadata
"""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


class ExtensionError(Exception):
    """Base exception for extension operations."""
    pass


@dataclass
class ExtensionMetadata:
    """Metadata for a vCon extension."""
    extension_name: str
    extension_version: str
    vcon_version_compatibility: List[str]
    bundle_format_version: str
    description: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'extension_name': self.extension_name,
            'extension_version': self.extension_version,
            'vcon_version_compatibility': self.vcon_version_compatibility,
            'bundle_format_version': self.bundle_format_version,
            'description': self.description
        }
    
    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExtensionMetadata":
        """Create from dictionary."""
        return cls(
            extension_name=data['extension_name'],
            extension_version=data['extension_version'],
            vcon_version_compatibility=data['vcon_version_compatibility'],
            bundle_format_version=data['bundle_format_version'],
            description=data['description']
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> "ExtensionMetadata":
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


class ExtensionHandler:
    """
    Handles vCon extensions in bundles.
    
    Extensions are stored in the extensions/ directory with structure:
    extensions/
    └── [extension-name]/
        ├── metadata.json
        └── files/
            └── [hash-based-names]
    """
    
    def detect_extensions(self, vcon_data: Dict[str, Any]) -> List[str]:
        """
        Detect extensions used in a vCon.
        
        Args:
            vcon_data: Parsed vCon data
            
        Returns:
            List of extension names
        """
        extensions = []
        
        # Check for custom fields that might indicate extensions
        # Extensions typically add custom top-level fields or use specific namespaces
        known_core_fields = {
            'vcon', 'uuid', 'created_at', 'updated_at', 'subject',
            'parties', 'dialog', 'analysis', 'attachments', 'group',
            'redacted', 'appended'
        }
        
        # Look for non-standard fields
        for key in vcon_data.keys():
            if key not in known_core_fields:
                # Possible extension field
                extensions.append(key)
        
        return extensions
    
    def bundle_extension(
        self,
        extension_name: str,
        metadata: ExtensionMetadata,
        files: Optional[Dict[str, bytes]] = None
    ) -> Dict[str, Any]:
        """
        Prepare extension data for bundling.
        
        Args:
            extension_name: Name of the extension
            metadata: Extension metadata
            files: Optional dictionary of filename -> file data
            
        Returns:
            Dictionary with extension data ready for bundling
        """
        extension_data = {
            'name': extension_name,
            'metadata': metadata.to_dict(),
            'files': files or {}
        }
        
        return extension_data
    
    def extract_extension(
        self,
        bundle_path: Path,
        extension_name: str
    ) -> Optional[Dict[str, Any]]:
        """
        Extract extension data from bundle.
        
        Args:
            bundle_path: Path to bundle (or extracted directory)
            extension_name: Name of extension to extract
            
        Returns:
            Dictionary with extension data or None if not found
        """
        extension_dir = bundle_path / 'extensions' / extension_name
        
        if not extension_dir.exists():
            return None
        
        # Load metadata
        metadata_file = extension_dir / 'metadata.json'
        if not metadata_file.exists():
            raise ExtensionError(f"Extension {extension_name} missing metadata.json")
        
        try:
            metadata_str = metadata_file.read_text()
            metadata = ExtensionMetadata.from_json(metadata_str)
        except Exception as e:
            raise ExtensionError(f"Failed to parse extension metadata: {e}")
        
        # Load files if present
        files_dir = extension_dir / 'files'
        extension_files = {}
        
        if files_dir.exists():
            for file_path in files_dir.iterdir():
                if file_path.is_file():
                    extension_files[file_path.name] = file_path.read_bytes()
        
        return {
            'name': extension_name,
            'metadata': metadata,
            'files': extension_files
        }
    
    def list_extensions(self, bundle_path: Path) -> List[str]:
        """
        List all extensions in a bundle.
        
        Args:
            bundle_path: Path to bundle (or extracted directory)
            
        Returns:
            List of extension names
        """
        extensions_dir = bundle_path / 'extensions'
        
        if not extensions_dir.exists():
            return []
        
        extensions = []
        for item in extensions_dir.iterdir():
            if item.is_dir():
                extensions.append(item.name)
        
        return extensions
    
    def validate_extension(
        self,
        extension_data: Dict[str, Any],
        bundle_format_version: str = "1.0"
    ) -> bool:
        """
        Validate extension compatibility with bundle format.
        
        Args:
            extension_data: Extension data dictionary
            bundle_format_version: Bundle format version
            
        Returns:
            True if compatible, False otherwise
        """
        if 'metadata' not in extension_data:
            return False
        
        metadata = extension_data['metadata']
        
        if isinstance(metadata, ExtensionMetadata):
            return metadata.bundle_format_version == bundle_format_version
        elif isinstance(metadata, dict):
            return metadata.get('bundle_format_version') == bundle_format_version
        
        return False


def create_extension_metadata(
    name: str,
    version: str,
    description: str,
    vcon_versions: Optional[List[str]] = None,
    bundle_version: str = "1.0"
) -> ExtensionMetadata:
    """
    Create extension metadata.
    
    Args:
        name: Extension name
        version: Extension version
        description: Extension description
        vcon_versions: Compatible vCon versions (default: ["0.3.0"])
        bundle_version: Bundle format version (default: "1.0")
        
    Returns:
        ExtensionMetadata instance
    """
    if vcon_versions is None:
        vcon_versions = ["0.3.0"]
    
    return ExtensionMetadata(
        extension_name=name,
        extension_version=version,
        vcon_version_compatibility=vcon_versions,
        bundle_format_version=bundle_version,
        description=description
    )

