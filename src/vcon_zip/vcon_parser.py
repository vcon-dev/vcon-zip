"""
vCon parser for handling all security forms (unsigned, JWS signed, JWE encrypted).

Supports parsing vCons and extracting external file references while preserving
the original security form structure.
"""

import json
import base64
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass
from enum import Enum


class SecurityForm(Enum):
    """vCon security forms as defined in the vCon specification."""
    UNSIGNED = "unsigned"
    SIGNED = "signed"  # JWS
    ENCRYPTED = "encrypted"  # JWE


class VConParserError(Exception):
    """Raised when vCon parsing fails."""
    pass


@dataclass
class ExternalReference:
    """Represents an external file reference in a vCon."""
    url: str
    content_hash: Any  # Can be string or list of strings
    mimetype: Optional[str] = None
    reference_type: str = "unknown"  # dialog, attachment, analysis, group


@dataclass
class ParsedVCon:
    """Result of parsing a vCon."""
    uuid: str
    security_form: SecurityForm
    original_content: str  # Original JSON/JWS/JWE string
    vcon_data: Dict[str, Any]  # Parsed vCon data (decrypted/unsigned payload)
    external_references: List[ExternalReference]


class VConParser:
    """
    Parser for vCon files in all security forms.
    
    Handles:
    - Unsigned vCons (plain JSON)
    - Signed vCons (JWS format)
    - Encrypted vCons (JWE format)
    """
    
    def __init__(self, decryption_key: Optional[Any] = None):
        """
        Initialize vCon parser.
        
        Args:
            decryption_key: Optional key for decrypting JWE vCons
        """
        self.decryption_key = decryption_key
    
    def parse(self, vcon_content: str) -> ParsedVCon:
        """
        Parse a vCon in any security form.
        
        Args:
            vcon_content: vCon content as JSON string
            
        Returns:
            ParsedVCon with extracted information
            
        Raises:
            VConParserError: If parsing fails
        """
        try:
            data = json.loads(vcon_content)
        except json.JSONDecodeError as e:
            raise VConParserError(f"Invalid JSON: {e}")
        
        # Detect security form
        security_form = self._detect_security_form(data)
        
        if security_form == SecurityForm.UNSIGNED:
            return self._parse_unsigned(vcon_content, data)
        elif security_form == SecurityForm.SIGNED:
            return self._parse_jws(vcon_content, data)
        elif security_form == SecurityForm.ENCRYPTED:
            return self._parse_jwe(vcon_content, data)
        else:
            raise VConParserError(f"Unknown security form: {security_form}")
    
    def _detect_security_form(self, data: Dict[str, Any]) -> SecurityForm:
        """
        Detect vCon security form from structure.
        
        Args:
            data: Parsed JSON data
            
        Returns:
            SecurityForm enum value
        """
        # JWS has 'payload', 'protected', 'signature' at top level
        if 'payload' in data and 'protected' in data:
            return SecurityForm.SIGNED
        
        # JWE has 'protected', 'encrypted_key', 'iv', 'ciphertext', 'tag'
        if 'ciphertext' in data and 'encrypted_key' in data:
            return SecurityForm.ENCRYPTED
        
        # Otherwise assume unsigned (has vcon field)
        if 'vcon' in data:
            return SecurityForm.UNSIGNED
        
        raise VConParserError("Unable to detect vCon security form")
    
    def _parse_unsigned(self, original_content: str, data: Dict[str, Any]) -> ParsedVCon:
        """
        Parse an unsigned vCon.
        
        Args:
            original_content: Original JSON string
            data: Parsed vCon data
            
        Returns:
            ParsedVCon
        """
        uuid = self._extract_uuid(data)
        external_refs = self._extract_external_references(data)
        
        return ParsedVCon(
            uuid=uuid,
            security_form=SecurityForm.UNSIGNED,
            original_content=original_content,
            vcon_data=data,
            external_references=external_refs
        )
    
    def _parse_jws(self, original_content: str, data: Dict[str, Any]) -> ParsedVCon:
        """
        Parse a JWS signed vCon.
        
        Args:
            original_content: Original JWS JSON string
            data: Parsed JWS structure
            
        Returns:
            ParsedVCon with payload extracted
        """
        if 'payload' not in data:
            raise VConParserError("JWS missing payload field")
        
        # Decode base64url payload
        try:
            # Add padding if needed
            payload_b64 = data['payload']
            padding = 4 - (len(payload_b64) % 4)
            if padding != 4:
                payload_b64 += '=' * padding
            
            payload_bytes = base64.urlsafe_b64decode(payload_b64)
            payload_str = payload_bytes.decode('utf-8')
            vcon_data = json.loads(payload_str)
        except Exception as e:
            raise VConParserError(f"Failed to decode JWS payload: {e}")
        
        uuid = self._extract_uuid(vcon_data)
        external_refs = self._extract_external_references(vcon_data)
        
        return ParsedVCon(
            uuid=uuid,
            security_form=SecurityForm.SIGNED,
            original_content=original_content,
            vcon_data=vcon_data,
            external_references=external_refs
        )
    
    def _parse_jwe(self, original_content: str, data: Dict[str, Any]) -> ParsedVCon:
        """
        Parse a JWE encrypted vCon.
        
        Args:
            original_content: Original JWE JSON string
            data: Parsed JWE structure
            
        Returns:
            ParsedVCon (may have empty vcon_data if decryption key unavailable)
            
        Raises:
            VConParserError: If decryption is attempted but fails
        """
        # If no decryption key, return with minimal information
        if self.decryption_key is None:
            # Try to extract UUID from protected header if available
            uuid = self._try_extract_uuid_from_jwe_header(data)
            
            return ParsedVCon(
                uuid=uuid,
                security_form=SecurityForm.ENCRYPTED,
                original_content=original_content,
                vcon_data={},
                external_references=[]
            )
        
        # Decrypt JWE (requires security module)
        from .security import JWEDecryptor
        
        decryptor = JWEDecryptor(self.decryption_key)
        try:
            decrypted_content = decryptor.decrypt(original_content)
            
            # Decrypted content might itself be signed (JWS)
            decrypted_data = json.loads(decrypted_content)
            inner_form = self._detect_security_form(decrypted_data)
            
            if inner_form == SecurityForm.SIGNED:
                # Recursively parse inner JWS
                inner_parsed = self._parse_jws(decrypted_content, decrypted_data)
                vcon_data = inner_parsed.vcon_data
                external_refs = inner_parsed.external_references
            else:
                vcon_data = decrypted_data
                external_refs = self._extract_external_references(vcon_data)
            
            uuid = self._extract_uuid(vcon_data)
            
            return ParsedVCon(
                uuid=uuid,
                security_form=SecurityForm.ENCRYPTED,
                original_content=original_content,
                vcon_data=vcon_data,
                external_references=external_refs
            )
        except Exception as e:
            raise VConParserError(f"Failed to decrypt JWE: {e}")
    
    def _extract_uuid(self, vcon_data: Dict[str, Any]) -> str:
        """
        Extract UUID from vCon data.
        
        Args:
            vcon_data: Parsed vCon data
            
        Returns:
            UUID string
            
        Raises:
            VConParserError: If UUID is missing
        """
        if 'uuid' not in vcon_data:
            raise VConParserError("vCon missing required 'uuid' field")
        
        return vcon_data['uuid']
    
    def _try_extract_uuid_from_jwe_header(self, jwe_data: Dict[str, Any]) -> str:
        """
        Try to extract UUID from JWE protected header.
        
        Args:
            jwe_data: Parsed JWE structure
            
        Returns:
            UUID if found, otherwise generates placeholder
        """
        # This is a fallback for encrypted vCons without decryption keys
        # In practice, we may need to generate a temporary UUID or fail
        try:
            if 'protected' in jwe_data:
                protected_b64 = jwe_data['protected']
                padding = 4 - (len(protected_b64) % 4)
                if padding != 4:
                    protected_b64 += '=' * padding
                
                protected_bytes = base64.urlsafe_b64decode(protected_b64)
                protected_data = json.loads(protected_bytes)
                
                # Check for UUID in header (non-standard but possible)
                if 'kid' in protected_data and len(protected_data['kid']) == 36:
                    return protected_data['kid']
        except:
            pass
        
        raise VConParserError("Cannot extract UUID from encrypted vCon without decryption key")
    
    def _extract_external_references(self, vcon_data: Dict[str, Any]) -> List[ExternalReference]:
        """
        Extract all external file references from vCon data.
        
        Args:
            vcon_data: Parsed vCon data
            
        Returns:
            List of ExternalReference objects
        """
        references = []
        
        # Check dialog array
        for item in vcon_data.get('dialog', []):
            if 'url' in item and 'content_hash' in item:
                references.append(ExternalReference(
                    url=item['url'],
                    content_hash=item['content_hash'],
                    mimetype=item.get('mimetype'),
                    reference_type='dialog'
                ))
        
        # Check attachments array
        for item in vcon_data.get('attachments', []):
            if 'url' in item and 'content_hash' in item:
                references.append(ExternalReference(
                    url=item['url'],
                    content_hash=item['content_hash'],
                    mimetype=item.get('mimetype'),
                    reference_type='attachment'
                ))
        
        # Check analysis array
        for item in vcon_data.get('analysis', []):
            if 'url' in item and 'content_hash' in item:
                references.append(ExternalReference(
                    url=item['url'],
                    content_hash=item['content_hash'],
                    mimetype=item.get('mimetype'),
                    reference_type='analysis'
                ))
        
        # Check group array (for referenced vCons)
        for item in vcon_data.get('group', []):
            if 'url' in item and 'content_hash' in item:
                references.append(ExternalReference(
                    url=item['url'],
                    content_hash=item['content_hash'],
                    mimetype=item.get('mimetype'),
                    reference_type='group'
                ))
        
        return references

