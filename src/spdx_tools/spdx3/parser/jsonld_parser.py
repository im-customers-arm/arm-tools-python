# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json
import logging
from typing import Any, Dict, List, Optional, TypeVar, cast

from spdx_tools.spdx3.model import (
    Bundle,
    CreationInfo,
    ExternalIdentifier,
    ExternalMap,
    ExternalReference,
    IntegrityMethod,
    NamespaceMap,
    SpdxDocument,
)
from spdx_tools.spdx3.validation.jsonld_validator import JSONLDSchemaValidator

logger = logging.getLogger(__name__)

T = TypeVar("T")

class ParserException(Exception):
    """Exception raised for errors during parsing."""
    pass

class JSONLDV3Parser:
    """Parser for SPDX v3 JSON-LD files."""
    
    def __init__(self, validate: bool = True):
        """Initialize the parser.
        
        Args:
            validate: Whether to validate the document against the schema before parsing
        """
        self.validate = validate
        if validate:
            self.validator = JSONLDSchemaValidator()
    
    def parse_document(self, document: Dict[str, Any]) -> SpdxDocument:
        """
        Parse an SPDX v3 document dictionary into an SpdxDocument object.
        
        Args:
            document: The parsed JSON-LD document as a dictionary
            
        Returns:
            An SpdxDocument object
        """
        if self.validate:
            errors = self.validator.validate(document)
            if errors:
                error_msg = "\n".join(errors)
                raise ParserException(f"Invalid SPDX v3 document:\n{error_msg}")
        
        try:
            # Extract basic fields
            spdx_id = self._get_required(document, "id")
            name = self._get_required(document, "name")
            element = self._get_list_field(document, "element", [])
            root_element = self._get_list_field(document, "rootElement", [])
            
            # Optional fields
            summary = self._get_optional(document, "summary")
            description = self._get_optional(document, "description")
            comment = self._get_optional(document, "comment")
            extension = self._get_optional(document, "extension")
            context = self._get_optional(document, "context")
            
            # Parse complex objects
            creation_info = self._parse_creation_info(document.get("creationInfo"))
            verified_using = self._parse_integrity_methods(document.get("verifiedUsing", []))
            external_reference = self._parse_external_references(document.get("externalReference", []))
            external_identifier = self._parse_external_identifiers(document.get("externalIdentifier", []))
            namespaces = self._parse_namespace_maps(document.get("namespaces", []))
            imports = self._parse_external_maps(document.get("imports", []))
            
            # Create the SpdxDocument instance
            spdx_doc = SpdxDocument(
                spdx_id=spdx_id,
                name=name,
                element=element,
                root_element=root_element,
                creation_info=creation_info,
                summary=summary,
                description=description,
                comment=comment,
                verified_using=verified_using,
                external_reference=external_reference,
                external_identifier=external_identifier,
                extension=extension,
                namespaces=namespaces,
                imports=imports,
                context=context,
            )
            
            return spdx_doc
        
        except KeyError as e:
            raise ParserException(f"Missing required field: {e}")
        except Exception as e:
            raise ParserException(f"Error parsing SPDX v3 document: {e}")
    
    def parse_file(self, file_path: str) -> SpdxDocument:
        """
        Parse an SPDX v3 JSON-LD file into an SpdxDocument object.
        
        Args:
            file_path: Path to the JSON-LD file
            
        Returns:
            An SpdxDocument object
        """
        try:
            with open(file_path, 'r') as f:
                document = json.load(f)
        except json.JSONDecodeError as e:
            raise ParserException(f"Invalid JSON in file {file_path}: {str(e)}")
        except FileNotFoundError:
            raise ParserException(f"File not found: {file_path}")
        
        return self.parse_document(document)
    
    def parse_json_string(self, json_string: str) -> SpdxDocument:
        """
        Parse an SPDX v3 JSON-LD string into an SpdxDocument object.
        
        Args:
            json_string: JSON-LD content as a string
            
        Returns:
            An SpdxDocument object
        """
        try:
            document = json.loads(json_string)
        except json.JSONDecodeError as e:
            raise ParserException(f"Invalid JSON string: {str(e)}")
        
        return self.parse_document(document)
    
    def _get_required(self, obj: Dict[str, Any], key: str) -> Any:
        """Get a required field from an object."""
        if key not in obj:
            raise KeyError(key)
        return obj[key]
    
    def _get_optional(self, obj: Dict[str, Any], key: str) -> Optional[Any]:
        """Get an optional field from an object."""
        return obj.get(key)
    
    def _get_list_field(self, obj: Dict[str, Any], key: str, default: List[Any] = None) -> List[Any]:
        """Get a list field from an object."""
        if default is None:
            default = []
        value = obj.get(key, default)
        if not isinstance(value, list):
            return [value]
        return value
    
    def _parse_creation_info(self, info: Optional[Dict[str, Any]]) -> Optional[CreationInfo]:
        """Parse creation info object."""
        if not info:
            return None
        
        # Implementation details will depend on CreationInfo class structure
        # For now, we'll return None
        return None
    
    def _parse_integrity_methods(self, methods: List[Dict[str, Any]]) -> List[IntegrityMethod]:
        """Parse integrity methods."""
        # Placeholder implementation
        return []
    
    def _parse_external_references(self, references: List[Dict[str, Any]]) -> List[ExternalReference]:
        """Parse external references."""
        # Placeholder implementation
        return []
    
    def _parse_external_identifiers(self, identifiers: List[Dict[str, Any]]) -> List[ExternalIdentifier]:
        """Parse external identifiers."""
        # Placeholder implementation
        return []
    
    def _parse_namespace_maps(self, namespaces: List[Dict[str, Any]]) -> List[NamespaceMap]:
        """Parse namespace maps."""
        # Placeholder implementation
        return []
    
    def _parse_external_maps(self, maps: List[Dict[str, Any]]) -> List[ExternalMap]:
        """Parse external maps."""
        # Placeholder implementation
        return []

