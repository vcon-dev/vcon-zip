"""
vCon Zip Bundle - Python implementation of the vCon Zip Bundle format.

This package provides tools for creating, extracting, and validating vCon Zip Bundles (.vconz),
which package one or more vCon conversation data containers with their associated media files.
"""

__version__ = "1.0.0"

from .bundle import BundleCreator, BundleExtractor
from .validation import BundleValidator

__all__ = [
    "BundleCreator",
    "BundleExtractor",
    "BundleValidator",
]

