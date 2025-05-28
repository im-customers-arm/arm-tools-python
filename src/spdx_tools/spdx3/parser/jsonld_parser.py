# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json
import logging
from datetime import datetime
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, TypeVar, cast, Union

from spdx_tools.spdx3.model import CreationInfo
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.model.software import File, Package
from spdx_tools.spdx3.model.relationship import Relationship, RelationshipType, RelationshipCompleteness


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

    def build_spdx_v3_payload(self, document: Dict[str, Any]) -> Payload:
        payload = Payload()
        
        spdx_document = self.parse_document(document)
        payload.add_element(spdx_document)
        
        self._parse_graph(document, payload)
        
        # TODO: Check if these properties are in the object.
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

    def _parse_graph(self, document: Dict[str, Any], payload: Payload) -> None:
        """Parse the entire SPDX v3 graph and add elements to a Payload."""
        graph = document.get("@graph", [])

        if not graph:
            raise ParserException("Missing @graph element in SPDX v3 JSON-LD document")
        
        # Build reference map
        self._build_object_map(graph)
        
        # Process each object in the graph based on its type
        for obj in graph:
            obj_type = obj.get("type") or obj.get("@type")

            if obj_type == "SpdxDocument":
                document = self._parse_document_object(obj, document.get("@context"))
                payload.add_element(document)

            elif obj_type in ["Package", "software_Package"]:
                package = self._parse_package(obj)
                if package:
                    payload.add_element(package)

            elif obj_type in ["File", "software_File"]:
                file = self._parse_file(obj)
                if file:
                    payload.add_element(file)

            elif obj_type == "Relationship":
                relationship = self._parse_relationship(obj)
                if relationship:
                    payload.add_element(relationship)

            # --- Extension/Profile support ---
            elif obj_type in ["Build", "build_Build"]:
                build = self._parse_build(obj)
                if build:
                    payload.add_element(build)

            elif obj_type in ["AI", "ai_AI"]:
                ai = self._parse_ai(obj)
                if ai:
                    payload.add_element(ai)

            elif obj_type in ["Dataset", "dataset_Dataset"]:
                dataset = self._parse_dataset(obj)
                if dataset:
                    payload.add_element(dataset)

            elif obj_type in ["Licensing", "licensing_Licensing"]:
                licensing = self._parse_licensing(obj)
                if licensing:
                    payload.add_element(licensing)

            # --- Security extension/profile support ---
            elif obj_type in [
                "Vulnerability", "security_Vulnerability",
                "CvssV3VulnAssessmentRelationship", "security_CvssV3VulnAssessmentRelationship",
                "CvssV2VulnAssessmentRelationship", "security_CvssV2VulnAssessmentRelationship",
                "SsvcVulnAssessmentRelationship", "security_SsvcVulnAssessmentRelationship"
            ]:
                security_obj = self._parse_security(obj)
                if security_obj:
                    payload.add_element(security_obj)

            # --- Software extension/profile support ---
            elif obj_type in [
                "SoftwarePurpose", "software_SoftwarePurpose",
                "SoftwareVersion", "software_SoftwareVersion",
                "SoftwareBuild", "software_SoftwareBuild",
                "SoftwareValidation", "software_SoftwareValidation",
                "SoftwareAttribution", "software_SoftwareAttribution",
                "SoftwareRelease", "software_SoftwareRelease",
                "SoftwareDependency", "software_SoftwareDependency"
            ]:
                software_obj = self._parse_software(obj)
                if software_obj:
                    payload.add_element(software_obj)

            # Generic handler for unknown/custom extension types
            else:
                extension_element = self._parse_extension_object(obj)
                if extension_element:
                    payload.add_element(extension_element)

    # --- Extension/Profile Parsers ---
    def _parse_build(self, obj: Dict[str, Any]):
        """Parse a Build extension/profile object from JSON-LD."""
        from spdx_tools.spdx3.model.build.build import Build
        try:
            # Extract required fields for Build extension
            spdx_id = self._get_required(obj, "spdxId")
            name = self._get_required(obj, "name")
            # Optional fields
            build_system = self._get_optional(obj, "buildSystem")
            build_script = self._get_optional(obj, "buildScript")
            build_env = self._get_optional(obj, "buildEnvironment")
            comment = self._get_optional(obj, "comment")
            # Creation info
            creation_info = None
            creation_info_ref = obj.get("creationInfo")
            if creation_info_ref:
                creation_info_obj = self._resolve_reference(creation_info_ref)
                if creation_info_obj:
                    creation_info = self._parse_creation_info(creation_info_obj)
            return Build(
                spdx_id=spdx_id,
                name=name,
                build_system=build_system,
                build_script=build_script,
                build_environment=build_env,
                comment=comment,
                creation_info=creation_info,
            )
        except Exception as e:
            logger.warning(f"Error parsing Build extension: {str(e)}")
            return None

    def _parse_ai(self, obj: Dict[str, Any]):
        """Parse an AI extension/profile object from JSON-LD."""
        from spdx_tools.spdx3.model.ai.ai import AI
        try:
            spdx_id = self._get_required(obj, "spdxId")
            name = self._get_required(obj, "name")
            ai_type = self._get_optional(obj, "aiType")
            ai_framework = self._get_optional(obj, "aiFramework")
            ai_model = self._get_optional(obj, "aiModel")
            comment = self._get_optional(obj, "comment")
            creation_info = None
            creation_info_ref = obj.get("creationInfo")
            if creation_info_ref:
                creation_info_obj = self._resolve_reference(creation_info_ref)
                if creation_info_obj:
                    creation_info = self._parse_creation_info(creation_info_obj)
            return AI(
                spdx_id=spdx_id,
                name=name,
                ai_type=ai_type,
                ai_framework=ai_framework,
                ai_model=ai_model,
                comment=comment,
                creation_info=creation_info,
            )
        except Exception as e:
            logger.warning(f"Error parsing AI extension: {str(e)}")
            return None

    def _parse_dataset(self, obj: Dict[str, Any]):
        """Parse a Dataset extension/profile object from JSON-LD."""
        from spdx_tools.spdx3.model.dataset.dataset import Dataset
        try:
            spdx_id = self._get_required(obj, "spdxId")
            name = self._get_required(obj, "name")
            dataset_type = self._get_optional(obj, "datasetType")
            dataset_format = self._get_optional(obj, "datasetFormat")
            dataset_size = self._get_optional(obj, "datasetSize")
            comment = self._get_optional(obj, "comment")
            creation_info = None
            creation_info_ref = obj.get("creationInfo")
            if creation_info_ref:
                creation_info_obj = self._resolve_reference(creation_info_ref)
                if creation_info_obj:
                    creation_info = self._parse_creation_info(creation_info_obj)
            return Dataset(
                spdx_id=spdx_id,
                name=name,
                dataset_type=dataset_type,
                dataset_format=dataset_format,
                dataset_size=dataset_size,
                comment=comment,
                creation_info=creation_info,
            )
        except Exception as e:
            logger.warning(f"Error parsing Dataset extension: {str(e)}")
            return None

    def _parse_licensing(self, obj: Dict[str, Any]):
        """Parse a Licensing extension/profile object from JSON-LD."""
        from spdx_tools.spdx3.model.licensing.licensing import Licensing
        try:
            spdx_id = self._get_required(obj, "spdxId")
            name = self._get_required(obj, "name")
            license_expression = self._get_optional(obj, "licenseExpression")
            license_list_version = self._get_optional(obj, "licenseListVersion")
            comment = self._get_optional(obj, "comment")
            creation_info = None
            creation_info_ref = obj.get("creationInfo")
            if creation_info_ref:
                creation_info_obj = self._resolve_reference(creation_info_ref)
                if creation_info_obj:
                    creation_info = self._parse_creation_info(creation_info_obj)
            return Licensing(
                spdx_id=spdx_id,
                name=name,
                license_expression=license_expression,
                license_list_version=license_list_version,
                comment=comment,
                creation_info=creation_info,
            )
        except Exception as e:
            logger.warning(f"Error parsing Licensing extension: {str(e)}")
            return None

    def _parse_extension_object(self, obj: Dict[str, Any]):
        """Generic handler for unknown/custom extension/profile types."""
        try:
            from spdx_tools.spdx3.model.extension_element import ExtensionElement
            return ExtensionElement.from_json(obj)
        except Exception as e:
            logger.warning(f"Error parsing unknown/custom extension object: {str(e)}")
            return None

    def _parse_document_object(self, obj: Dict[str, Any], context: Optional[str]) -> SpdxDocument:
        """
        Parse an SpdxDocument object from JSON-LD.
        
        Args:
            obj: The JSON object representing the SpdxDocument
            context: The JSON-LD context string
            
        Returns:
            An SpdxDocument object
        """
        # Extract required fields
        spdx_id = self._get_required(obj, "spdxId")
        name = self._get_required(obj, "name")
        
        # Extract optional fields with defaults
        element = self._get_list_field(obj, "element", [])
        root_element = self._get_list_field(obj, "rootElement", [])
        summary = self._get_optional(obj, "summary")
        description = self._get_optional(obj, "description")
        comment = self._get_optional(obj, "comment")
        extension = self._get_optional(obj, "extension")
        
        # Handle creation info (reference to another object)
        creation_info_ref = obj.get("creationInfo")
        creation_info = None
        if creation_info_ref:
            creation_info_obj = self._resolve_reference(creation_info_ref)
            if creation_info_obj:
                creation_info = self._parse_creation_info(creation_info_obj)
        
        # Create and return the document
        return SpdxDocument(
            spdx_id=spdx_id,
            name=name,
            element=element,
            root_element=root_element,
            creation_info=creation_info,
            summary=summary,
            description=description,
            comment=comment,
            verified_using=[],  # For simplicity, using empty lists for complex types
            external_reference=[],
            external_identifier=[],
            extension=extension,
            namespaces=[],
            imports=[],
            context=context,
        )

    def _parse_package(self, obj: Dict[str, Any]) -> Optional[Package]:
        """
        Parse a Package object from JSON-LD.
        
        Args:
            obj: The JSON object representing the Package
            
        Returns:
            A Package object or None if parsing fails
        """
        try:
            # Extract required fields
            spdx_id = self._get_required(obj, "spdxId")
            name = self._get_required(obj, "name")
            
            # Extract optional fields
            version = self._get_optional(obj, "packageVersion")
            summary = self._get_optional(obj, "summary")
            description = self._get_optional(obj, "description")
            comment = self._get_optional(obj, "comment")
            download_location = self._get_optional(obj, "downloadLocation")
            
            # Parse supplier and originator (if any)
            supplier = self._get_optional(obj, "supplier")
            originator = self._get_optional(obj, "originator")
            
            # Handle copyright text
            copyright_text = self._get_optional(obj, "software_copyrightText")
            
            # Handle creation info
            creation_info_ref = obj.get("creationInfo")
            creation_info = None
            if creation_info_ref:
                creation_info_obj = self._resolve_reference(creation_info_ref)
                if creation_info_obj:
                    creation_info = self._parse_creation_info(creation_info_obj)
            
            # Create and return the package
            return Package(
                spdx_id=spdx_id,
                name=name,
                version=version,
                summary=summary,
                description=description,
                comment=comment,
                download_location=download_location,
                supplier=supplier,
                originator=originator,
                copyright_text=copyright_text,
                creation_info=creation_info,
                # For simplicity, using empty lists for complex types
                primary_purpose=[],
                built_time=None,
                release_time=None,
                validated=None,
                attribution_text=[],
                verified_using=[],
                external_reference=[],
                external_identifier=[],
                extension=None,
            )
        except Exception as e:
            logger.warning(f"Error parsing Package: {str(e)}")
            return None

    def _parse_file(self, obj: Dict[str, Any]) -> Optional[File]:
        """
        Parse a File object from JSON-LD.
        
        Args:
            obj: The JSON object representing the File
            
        Returns:
            A File object or None if parsing fails
        """
        try:
            # Extract required fields
            spdx_id = self._get_required(obj, "spdxId")
            name = self._get_required(obj, "name")
            
            # Extract optional fields
            comment = self._get_optional(obj, "comment")
            copyright_text = self._get_optional(obj, "software_copyrightText")
            
            # Parse hashes if present
            verified_using_refs = self._get_list_field(obj, "verifiedUsing")
            verified_using = []
            for ref in verified_using_refs:
                hash_obj = self._resolve_reference(ref)
                if hash_obj and hash_obj.get("type") == "Hash":
                    # In a full implementation, you'd parse this into a proper Hash object
                    # Here we're just logging for simplicity
                    algorithm = hash_obj.get("algorithm")
                    hash_value = hash_obj.get("hashValue")
                    logger.debug(f"Found hash: {algorithm}:{hash_value}")
            
            # Handle creation info
            creation_info_ref = obj.get("creationInfo")
            creation_info = None
            if creation_info_ref:
                creation_info_obj = self._resolve_reference(creation_info_ref)
                if creation_info_obj:
                    creation_info = self._parse_creation_info(creation_info_obj)
            
            # Create and return the file
            return File(
                spdx_id=spdx_id,
                name=name,
                comment=comment,
                copyright_text=copyright_text,
                creation_info=creation_info,
                # For simplicity, using empty lists or None for complex types
                content_type=None,
                attribution_text=[],
                verified_using=verified_using,
                external_reference=[],
                external_identifier=[],
                extension=None,
            )
        except Exception as e:
            logger.warning(f"Error parsing File: {str(e)}")
            return None

    def _parse_relationship(self, obj: Dict[str, Any]) -> Optional[Relationship]:
        """
        Parse a Relationship object from JSON-LD.
        
        Args:
            obj: The JSON object representing the Relationship
            
        Returns:
            A Relationship object or None if parsing fails
        """
        try:
            # Extract required fields
            spdx_id = self._get_required(obj, "spdxId")
            from_element = self._get_required(obj, "from")
            to_elements = self._get_list_field(obj, "to")
            
            # Get relationship type and convert to enum
            relationship_type_str = self._get_required(obj, "relationshipType").upper()
            try:
                relationship_type = RelationshipType[relationship_type_str]
            except KeyError:
                # Fall back to OTHER if not recognized
                logger.warning(f"Unknown relationship type: {relationship_type_str}, using OTHER")
                relationship_type = RelationshipType.OTHER
            
            # Handle completeness
            completeness_str = self._get_optional(obj, "completeness")
            completeness = None
            if completeness_str:
                try:
                    completeness_str = completeness_str.upper()
                    if completeness_str == "NOASSERTION":
                        completeness_str = "NO_ASSERTION"  # Fix common mismatch
                    completeness = RelationshipCompleteness[completeness_str]
                except KeyError:
                    logger.warning(f"Unknown completeness value: {completeness_str}")
            
            # Get other fields
            comment = self._get_optional(obj, "comment")
            
            # Handle dates (if any)
            start_time_str = self._get_optional(obj, "startTime")
            end_time_str = self._get_optional(obj, "endTime")
            
            start_time = None
            end_time = None
            
            if start_time_str:
                start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
            if end_time_str:
                end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00'))
            
            # Handle creation info
            creation_info_ref = obj.get("creationInfo")
            creation_info = None
            if creation_info_ref:
                creation_info_obj = self._resolve_reference(creation_info_ref)
                if creation_info_obj:
                    creation_info = self._parse_creation_info(creation_info_obj)
            
            # Create and return the relationship
            return Relationship(
                spdx_id=spdx_id,
                from_element=from_element,
                to=to_elements,
                relationship_type=relationship_type,
                completeness=completeness,
                start_time=start_time,
                end_time=end_time,
                comment=comment,
                creation_info=creation_info,
            )
        except Exception as e:
            logger.warning(f"Error parsing Relationship: {str(e)}")
            return None

    def _parse_creation_info(self, obj: Optional[Dict[str, Any]]) -> Optional[CreationInfo]:
        """
        Parse a CreationInfo object from JSON-LD.
        
        Args:
            obj: The JSON object representing the CreationInfo
            
        Returns:
            A CreationInfo object or None if parsing fails
        """
        if not obj:
            return None
            
        try:
            # Extract fields
            created_str = obj.get("created")
            created_by = self._ensure_list(obj.get("createdBy", []))
            created_using = self._ensure_list(obj.get("createdUsing", []))
            spec_version = obj.get("specVersion")
            comment = obj.get("comment")
            
            # Parse datetime
            created = None
            if created_str:
                created = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
            
            # Create and return CreationInfo
            return CreationInfo(
                created=created,
                created_by=created_by,
                created_using=created_using,
                spec_version=spec_version,
                comment=comment,
            )
        except Exception as e:
            logger.warning(f"Error parsing CreationInfo: {str(e)}")
            return None

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

    def parse_file(self, file_path: str) -> Payload:
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
        
        payload = self.build_spdx_v3_payload(document)

        return payload
        

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
            if "SpdxDocument" in [obj.get("type"), obj.get("@type")] :
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
        if key in obj:
            return obj[key]

        if key == "spdxId":
            for alt in ["id", "@id"]:
                if alt in obj:
                    return obj[alt]

        raise KeyError(key)
    
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
    
    def _parse_security(self, obj: Dict[str, Any]):
        """Parse a Security extension/profile object from JSON-LD."""
        # This method will dispatch to the correct security type based on obj_type
        obj_type = obj.get("type") or obj.get("@type")
        try:
            if obj_type in ["Vulnerability", "security_Vulnerability"]:
                from spdx_tools.spdx3.model.security.vulnerability import Vulnerability
                spdx_id = self._get_required(obj, "spdxId")
                name = self._get_optional(obj, "name")
                summary = self._get_optional(obj, "summary")
                description = self._get_optional(obj, "description")
                comment = self._get_optional(obj, "comment")
                published_time = self._get_optional(obj, "publishedTime")
                modified_time = self._get_optional(obj, "modifiedTime")
                withdrawn_time = self._get_optional(obj, "withdrawnTime")
                creation_info = None
                creation_info_ref = obj.get("creationInfo")
                if creation_info_ref:
                    creation_info_obj = self._resolve_reference(creation_info_ref)
                    if creation_info_obj:
                        creation_info = self._parse_creation_info(creation_info_obj)
                # For simplicity, not parsing verified_using, external_reference, external_identifier, extension
                return Vulnerability(
                    spdx_id=spdx_id,
                    name=name,
                    summary=summary,
                    description=description,
                    comment=comment,
                    published_time=published_time,
                    modified_time=modified_time,
                    withdrawn_time=withdrawn_time,
                    creation_info=creation_info,
                )
            # Add more security types as needed, e.g. CVSS, VEX, SSVC, etc.
            elif obj_type in ["CvssV3VulnAssessmentRelationship", "security_CvssV3VulnAssessmentRelationship"]:
                from spdx_tools.spdx3.model.security.cvss_v3_vuln_assessment_relationship import CvssV3VulnAssessmentRelationship
                # Required fields
                spdx_id = self._get_required(obj, "spdxId")
                from_element = self._get_required(obj, "from")
                to = self._get_list_field(obj, "to")
                relationship_type = self._get_required(obj, "relationshipType")
                score = self._get_required(obj, "score")
                # Optional fields
                severity = self._get_optional(obj, "severity")
                vector = self._get_optional(obj, "vector")
                comment = self._get_optional(obj, "comment")
                # For simplicity, not parsing all fields
                return CvssV3VulnAssessmentRelationship(
                    spdx_id=spdx_id,
                    from_element=from_element,
                    to=to,
                    relationship_type=relationship_type,
                    score=score,
                    severity=severity,
                    vector=vector,
                    comment=comment,
                )
            elif obj_type in ["CvssV2VulnAssessmentRelationship", "security_CvssV2VulnAssessmentRelationship"]:
                from spdx_tools.spdx3.model.security.cvss_v2_vuln_assessment_relationship import CvssV2VulnAssessmentRelationship
                spdx_id = self._get_required(obj, "spdxId")
                from_element = self._get_required(obj, "from")
                to = self._get_list_field(obj, "to")
                relationship_type = self._get_required(obj, "relationshipType")
                score = self._get_required(obj, "score")
                severity = self._get_optional(obj, "severity")
                vector = self._get_optional(obj, "vector")
                comment = self._get_optional(obj, "comment")
                return CvssV2VulnAssessmentRelationship(
                    spdx_id=spdx_id,
                    from_element=from_element,
                    to=to,
                    relationship_type=relationship_type,
                    score=score,
                    severity=severity,
                    vector=vector,
                    comment=comment,
                )
            elif obj_type in ["SsvcVulnAssessmentRelationship", "security_SsvcVulnAssessmentRelationship"]:
                from spdx_tools.spdx3.model.security.ssvc_vuln_assessment_relationship import SsvcVulnAssessmentRelationship, SsvcDecisionType
                spdx_id = self._get_required(obj, "spdxId")
                from_element = self._get_required(obj, "from")
                to = self._get_list_field(obj, "to")
                relationship_type = self._get_required(obj, "relationshipType")
                decision_type_str = self._get_required(obj, "decisionType")
                try:
                    decision_type = SsvcDecisionType[decision_type_str.upper()]
                except Exception:
                    decision_type = None
                comment = self._get_optional(obj, "comment")
                return SsvcVulnAssessmentRelationship(
                    spdx_id=spdx_id,
                    from_element=from_element,
                    to=to,
                    relationship_type=relationship_type,
                    decision_type=decision_type,
                    comment=comment,
                )
            # Add more security types as needed
            else:
                logger.warning(f"Unknown security extension type: {obj_type}")
                return None
        except Exception as e:
            logger.warning(f"Error parsing Security extension: {str(e)}")
            return None

    def _parse_software(self, obj: Dict[str, Any]):
        """Parse a Software extension/profile object from JSON-LD."""
        obj_type = obj.get("type") or obj.get("@type")
        try:
            if obj_type in ["SoftwarePurpose", "software_SoftwarePurpose"]:
                from spdx_tools.spdx3.model.software.software_purpose import SoftwarePurpose
                spdx_id = self._get_required(obj, "spdxId")
                name = self._get_optional(obj, "name")
                description = self._get_optional(obj, "description")
                comment = self._get_optional(obj, "comment")
                return SoftwarePurpose(
                    spdx_id=spdx_id,
                    name=name,
                    description=description,
                    comment=comment,
                )
            elif obj_type in ["SoftwareVersion", "software_SoftwareVersion"]:
                from spdx_tools.spdx3.model.software.software_version import SoftwareVersion
                spdx_id = self._get_required(obj, "spdxId")
                version = self._get_required(obj, "version")
                comment = self._get_optional(obj, "comment")
                return SoftwareVersion(
                    spdx_id=spdx_id,
                    version=version,
                    comment=comment,
                )
            elif obj_type in ["SoftwareBuild", "software_SoftwareBuild"]:
                from spdx_tools.spdx3.model.software.software_build import SoftwareBuild
                spdx_id = self._get_required(obj, "spdxId")
                build_id = self._get_optional(obj, "buildId")
                build_system = self._get_optional(obj, "buildSystem")
                comment = self._get_optional(obj, "comment")
                return SoftwareBuild(
                    spdx_id=spdx_id,
                    build_id=build_id,
                    build_system=build_system,
                    comment=comment,
                )
            elif obj_type in ["SoftwareValidation", "software_SoftwareValidation"]:
                from spdx_tools.spdx3.model.software.software_validation import SoftwareValidation
                spdx_id = self._get_required(obj, "spdxId")
                validation_type = self._get_optional(obj, "validationType")
                comment = self._get_optional(obj, "comment")
                return SoftwareValidation(
                    spdx_id=spdx_id,
                    validation_type=validation_type,
                    comment=comment,
                )
            elif obj_type in ["SoftwareAttribution", "software_SoftwareAttribution"]:
                from spdx_tools.spdx3.model.software.software_attribution import SoftwareAttribution
                spdx_id = self._get_required(obj, "spdxId")
                attribution_text = self._get_optional(obj, "attributionText")
                comment = self._get_optional(obj, "comment")
                return SoftwareAttribution(
                    spdx_id=spdx_id,
                    attribution_text=attribution_text,
                    comment=comment,
                )
            elif obj_type in ["SoftwareRelease", "software_SoftwareRelease"]:
                from spdx_tools.spdx3.model.software.software_release import SoftwareRelease
                spdx_id = self._get_required(obj, "spdxId")
                release_time = self._get_optional(obj, "releaseTime")
                comment = self._get_optional(obj, "comment")
                return SoftwareRelease(
                    spdx_id=spdx_id,
                    release_time=release_time,
                    comment=comment,
                )
            elif obj_type in ["SoftwareDependency", "software_SoftwareDependency"]:
                from spdx_tools.spdx3.model.software.software_dependency import SoftwareDependency
                spdx_id = self._get_required(obj, "spdxId")
                dependency = self._get_optional(obj, "dependency")
                comment = self._get_optional(obj, "comment")
                return SoftwareDependency(
                    spdx_id=spdx_id,
                    dependency=dependency,
                    comment=comment,
                )
            else:
                logger.warning(f"Unknown software extension type: {obj_type}")
                return None
        except Exception as e:
            logger.warning(f"Error parsing Software extension: {str(e)}")
            return None
