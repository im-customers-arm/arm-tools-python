# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, TypeVar, cast, Union

from spdx_tools.spdx3.payload import Payload

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
        self.object_cache = {}  # Cache for resolved objects
    
    def build_payload(self, document: Dict[str, Any]) -> Payload:
        payload = Payload()
        
        document = self.parse_document(document)
        payload.add_element(document)
        
        # Other properties to get
        #  document_namespace: str = document.creation_info.document_namespace
        #  creation_info: CreationInfo = spdx_document.creation_info
        
        # These are added iteratively to the Payload instance.
        # packages
        # files
        # snippets
        # relationships # Note this has nuanced merging functionality. 
        # annotations
        
        return payload
    
    # Original entry point. Will replicate the bump from v2 workflow in this file.
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
            # Reset object cache for this parsing session
            self.object_cache = {}
            
            # Extract the graph array from the document
            graph = document.get("@graph", [])
            if not graph:
                raise ParserException("Missing @graph element in SPDX v3 JSON-LD document")
                
            # Build a map of all objects by their @id for reference resolution
            self._build_object_map(graph)
            
            # Find the SpdxDocument object in the graph
            spdx_doc_obj = self._find_spdx_document(graph)
            if not spdx_doc_obj:
                raise ParserException("Could not find SpdxDocument object in the graph")
            
            # Extract basic fields from the SPDX document object
            spdx_id = self._get_required(spdx_doc_obj, "spdxId")
            doc_type = self._get_optional(spdx_doc_obj, "type")
            data_license = self._get_optional(spdx_doc_obj, "dataLicense")
            name = self._get_required(spdx_doc_obj, "name")
            
            # Get lists (may need to resolve references)
            element = self._get_list_field(spdx_doc_obj, "element", [])
            root_element = self._get_list_field(spdx_doc_obj, "rootElement", [])
            
            # Optional fields
            summary = self._get_optional(spdx_doc_obj, "summary")
            description = self._get_optional(spdx_doc_obj, "description")
            comment = self._get_optional(spdx_doc_obj, "comment")
            extension = self._get_optional(spdx_doc_obj, "extension")
            context = self._get_optional(document, "@context")  # Context is usually at the root
            
            # Parse complex objects
            creation_info = self._parse_creation_info(self._resolve_reference(spdx_doc_obj.get("creationInfo")))
            verified_using = self._parse_integrity_methods(
                [self._resolve_reference(ref) for ref in self._ensure_list(spdx_doc_obj.get("verifiedUsing", []))]
            )
            external_reference = self._parse_external_references(
                [self._resolve_reference(ref) for ref in self._ensure_list(spdx_doc_obj.get("externalReference", []))]
            )
            external_identifier = self._parse_external_identifiers(
                [self._resolve_reference(ref) for ref in self._ensure_list(spdx_doc_obj.get("externalIdentifier", []))]
            )
            namespaces = self._parse_namespace_maps(
                [self._resolve_reference(ref) for ref in self._ensure_list(spdx_doc_obj.get("namespaces", []))]
            )
            imports = self._parse_external_maps(
                [self._resolve_reference(ref) for ref in self._ensure_list(spdx_doc_obj.get("imports", []))]
            )
            
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
    
    def _build_object_map(self, graph: List[Dict[str, Any]]) -> None:
        """
        Build a map of all objects in the graph by their @id.
        
        Args:
            graph: The @graph array from the JSON-LD document
        """
        for obj in graph:
            obj_id = obj.get("@id")
            if obj_id:
                self.object_cache[obj_id] = obj
            # Also index by spdxId if present
            spdx_id = obj.get("spdxId")
            if spdx_id:
                self.object_cache[spdx_id] = obj
    
    def _find_spdx_document(self, graph: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """
        Find the SpdxDocument object in the graph.
        
        Args:
            graph: The @graph array from the JSON-LD document
            
        Returns:
            The SpdxDocument object or None
        """
        for obj in graph:
            if obj.get("type") == "SpdxDocument":
                return obj
        return None
    
    def _resolve_reference(self, reference: Any) -> Any:
        """
        Resolve a reference to an object in the graph.
        
        Args:
            reference: String ID or object
            
        Returns:
            The resolved object or the original reference
        """
        if not reference or not isinstance(reference, str):
            return reference
            
        # If it's a string, try to look it up in the cache
        if reference in self.object_cache:
            return self.object_cache[reference]
            
        # If not found, return the original reference
        return reference
    
    def _ensure_list(self, value: Union[List[Any], Any]) -> List[Any]:
        """
        Ensure a value is a list.
        
        Args:
            value: Value to convert to list if not already
            
        Returns:
            List containing the value or empty list if value is None
        """
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]
    
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
        return self._ensure_list(value)
    
    def _parse_creation_info(self, info: Optional[Dict[str, Any]]) -> Optional[CreationInfo]:
        """Parse creation info object."""
        if not info:
            return None
        
        # Implementation details will depend on CreationInfo class structure
        # For now, we'll extract key fields and log them
        if isinstance(info, dict):
            logger.debug(f"Found CreationInfo with spec version: {info.get('specVersion')}")
        
        # Return None until we implement actual creation info parsing
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
