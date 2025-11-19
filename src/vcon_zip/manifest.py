"""
Manifest file handling for vCon Zip Bundle.

The manifest.json file contains bundle format identifiers and version information.
"""

import json
from typing import Dict, Any
from pathlib import Path


class ManifestError(Exception):
    """Raised when manifest validation or operations fail."""
    pass


class Manifest:
    """
    Represents a vCon Zip Bundle manifest.
    
    The manifest contains:
    - format: Must be "vcon-bundle"
    - version: Bundle format version (this spec defines "1.0")
    """
    
    REQUIRED_FORMAT = "vcon-bundle"
    CURRENT_VERSION = "1.0"
    
    def __init__(self, format: str = REQUIRED_FORMAT, version: str = CURRENT_VERSION):
        """
        Initialize a manifest.
        
        Args:
            format: Bundle format identifier (must be "vcon-bundle")
            version: Bundle format version
            
        Raises:
            ManifestError: If format is invalid
        """
        if format != self.REQUIRED_FORMAT:
            raise ManifestError(f"Invalid format: {format}, expected {self.REQUIRED_FORMAT}")
        
        self.format = format
        self.version = version
    
    def to_dict(self) -> Dict[str, str]:
        """
        Convert manifest to dictionary.
        
        Returns:
            Dictionary representation of manifest
        """
        return {
            "format": self.format,
            "version": self.version
        }
    
    def to_json(self) -> str:
        """
        Convert manifest to JSON string.
        
        Returns:
            JSON string representation
        """
        return json.dumps(self.to_dict(), indent=2)
    
    def save(self, path: Path) -> None:
        """
        Save manifest to file.
        
        Args:
            path: Path to save manifest.json
        """
        path.write_text(self.to_json())
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Manifest":
        """
        Create manifest from dictionary.
        
        Args:
            data: Dictionary containing manifest data
            
        Returns:
            Manifest instance
            
        Raises:
            ManifestError: If required fields are missing or invalid
        """
        if "format" not in data:
            raise ManifestError("Missing required field: format")
        
        if "version" not in data:
            raise ManifestError("Missing required field: version")
        
        return cls(format=data["format"], version=data["version"])
    
    @classmethod
    def from_json(cls, json_str: str) -> "Manifest":
        """
        Create manifest from JSON string.
        
        Args:
            json_str: JSON string
            
        Returns:
            Manifest instance
            
        Raises:
            ManifestError: If JSON is invalid or required fields are missing
        """
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError as e:
            raise ManifestError(f"Invalid JSON: {e}")
        
        return cls.from_dict(data)
    
    @classmethod
    def load(cls, path: Path) -> "Manifest":
        """
        Load manifest from file.
        
        Args:
            path: Path to manifest.json
            
        Returns:
            Manifest instance
            
        Raises:
            ManifestError: If file cannot be read or is invalid
        """
        try:
            json_str = path.read_text()
        except FileNotFoundError:
            raise ManifestError(f"Manifest file not found: {path}")
        except Exception as e:
            raise ManifestError(f"Error reading manifest: {e}")
        
        return cls.from_json(json_str)
    
    def is_version_supported(self) -> bool:
        """
        Check if manifest version is supported by this implementation.
        
        Returns:
            True if version is supported, False otherwise
        """
        # This implementation supports version 1.0
        # Future versions may add backward compatibility
        return self.version == "1.0"

