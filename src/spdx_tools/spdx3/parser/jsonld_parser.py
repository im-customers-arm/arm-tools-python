# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json
import logging
from datetime import datetime
from semantic_version import Version
from typing import Any, Dict, List, Optional, TypeVar, Union


from spdx_tools.spdx3.model import (
    CreationInfo,
    ExternalIdentifier,
    ExternalMap,
    ExternalReference,
    NamespaceMap,
    SpdxDocument,
)

from spdx_tools.spdx3.model.profile_identifier import ProfileIdentifierType
from spdx_tools.spdx3.model.relationship import Relationship, RelationshipType, RelationshipCompleteness
from spdx_tools.spdx3.model.software import File, Package
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.validation.jsonld_validator import JSONLDSchemaValidator
from spdx_tools.spdx3.model.hash import Hash, HashAlgorithm
from spdx_tools.spdx3.model.licensing import ListedLicense, CustomLicense
from spdx_tools.spdx3.model.licensing.license_field import LicenseField


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

            # Note that BASIL uses "Sbom" as the SpdxDocument type value.
            if obj_type in ["SpdxDocument", "Sbom"]:
                document = self._parse_document_element(obj, document.get("@context"))
                payload.add_element(document)

            elif obj_type in ["Package", "software_Package"]:
                package = self._parse_package(obj)
                if package:
                    payload.add_element(package)

            elif obj_type in ["File", "software_File"]:
                file = self._parse_file_element(obj)
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

            # TODO: Add generic handler for unknown/custom extension types
            else:
                pass

    # --- Extension/Profile Parsers ---
    def _parse_build(self, obj: Dict[str, Any]):
        """Parse a Build extension/profile object from JSON-LD."""
        from spdx_tools.spdx3.model.build.build import Build
        try:
            # Extract required fields for Build extension
            spdx_id = self._get_required(obj, "spdxId")
            build_type = self._get_required(obj, "build_type")
            name = self._get_required(obj, "name")
            # Optional fields
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
                build_type=build_type,
                name=name,
                comment=comment,
                creation_info=creation_info,
            )
        except Exception as e:
            logger.warning(f"Error parsing Build extension: {str(e)}")
            return None

    def _parse_ai(self, obj: Dict[str, Any]):
        """Parse an AI extension/profile object from JSON-LD."""
        from spdx_tools.spdx3.model.ai import AIPackage
        try:
            spdx_id = self._get_required(obj, "spdxId")
            name = self._get_required(obj, "name")
            comment = self._get_optional(obj, "comment")
            creation_info = None
            creation_info_ref = obj.get("creationInfo")
            supplied_by = obj.get('supplied_by', [])
            download_location = obj.get('download_location')
            package_version = obj.get('package_version')
            primary_purpose = obj.get('primary_purpose')
            release_time = obj.get('release_time')
            hyperparameter = obj.get('hyperparameter', {})

            if creation_info_ref:
                creation_info_obj = self._resolve_reference(creation_info_ref)
                if creation_info_obj:
                    creation_info = self._parse_creation_info(creation_info_obj)
            return AIPackage(
                spdx_id=spdx_id,
                name=name,
                comment=comment,
                creation_info=creation_info,
                supplied_by=supplied_by,
                download_location=download_location,
                package_version=package_version,
                primary_purpose=primary_purpose,
                release_time=release_time,
                hyperparameter=hyperparameter
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
            originated_by = self._get_required(obj, "originator")
            download_location = self._get_required(obj, "downloadLocation")
            primary_purpose = self._get_required(obj, "primaryPurpose")
            built_time = self._get_required(obj, "builtTime")
            release_time = self._get_required(obj, "releaseTime")
            dataset_type = self._get_optional(obj, "datasetType")
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
                originated_by=originated_by,
                download_location=download_location,
                built_time=built_time,
                primary_purpose=primary_purpose,
                release_time=release_time,
                dataset_type=dataset_type,
                dataset_size=dataset_size,
                comment=comment,
                creation_info=creation_info,
            )
        except Exception as e:
            logger.warning(f"Error parsing Dataset extension: {str(e)}")
            return None

    def _parse_license(self, obj: Dict[str, Any], license_key: str) -> Optional[LicenseField]:
        """
        Resolve and parse a license object (e.g., ListedLicense, CustomLicense) from a reference.
        Args:
            reference: String ID or dict representing the license
        Returns:
            Parsed license object or None
        """
        reference = self._get_optional(obj, license_key)

        if reference is None:
            return None

        obj = self._resolve_reference(reference)
        if not isinstance(obj, dict):
            return None

        obj_type = obj.get("type") or obj.get("@type")
        if obj_type in ["ListedLicense", "licensing_ListedLicense"]:
            try:
                license_id = self._get_required(obj, "@id")
                license_name = self._get_required(obj, "name")
                license_text = self._get_optional(obj, "licenseText")
                license_comment = self._get_optional(obj, "licenseComment")
                see_also = obj.get("seeAlso") or obj.get("seeAlsos") or []
                is_osi_approved = obj.get("isOsiApproved")
                is_fsf_libre = obj.get("isFsfLibre")
                standard_license_header = obj.get("standardLicenseHeader")
                standard_license_template = obj.get("standardLicenseTemplate")
                is_deprecated_license_id = obj.get("isDeprecatedLicenseId")
                obsoleted_by = obj.get("obsoletedBy")
                list_version_added = obj.get("listVersionAdded")
                deprecated_version = obj.get("deprecatedVersion")

                return ListedLicense(
                    license_id=license_id,
                    license_name=license_name,
                    license_text=license_text,
                    license_comment=license_comment,
                    see_also=see_also,
                    is_osi_approved=is_osi_approved,
                    is_fsf_libre=is_fsf_libre,
                    standard_license_header=standard_license_header,
                    standard_license_template=standard_license_template,
                    is_deprecated_license_id=is_deprecated_license_id,
                    obsoleted_by=obsoleted_by,
                    list_version_added=list_version_added,
                    deprecated_version=deprecated_version,
                )
            except Exception as e:
                logger.warning(f"Error parsing ListedLicense: {str(e)}")
                return None
        elif obj_type in ["CustomLicense", "licensing_CustomLicense"]:
            try:
                license_id = self._get_required(obj, "spdxId")
                license_name = self._get_required(obj, "name")
                license_text = self._get_optional(obj, "licenseText")
                license_comment = self._get_optional(obj, "licenseComment")
                see_also = obj.get("seeAlso") or obj.get("seeAlsos") or []
                is_osi_approved = obj.get("isOsiApproved")
                is_fsf_libre = obj.get("isFsfLibre")
                standard_license_header = obj.get("standardLicenseHeader")
                standard_license_template = obj.get("standardLicenseTemplate")
                is_deprecated_license_id = obj.get("isDeprecatedLicenseId")
                obsoleted_by = obj.get("obsoletedBy")
                return CustomLicense(
                    license_id=license_id,
                    license_name=license_name,
                    license_text=license_text,
                    license_comment=license_comment,
                    see_also=see_also,
                    is_osi_approved=is_osi_approved,
                    is_fsf_libre=is_fsf_libre,
                    standard_license_header=standard_license_header,
                    standard_license_template=standard_license_template,
                    is_deprecated_license_id=is_deprecated_license_id,
                    obsoleted_by=obsoleted_by,
                )
            except Exception as e:
                logger.warning(f"Error parsing CustomLicense: {str(e)}")
                return None
        else:
            logger.warning(f"Reference is not a recognized license type: {obj_type}")
            return None

    def _parse_document_element(self, obj: Dict[str, Any], context: Optional[str]) -> SpdxDocument:
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

        # Parse imports (ExternalMap list)
        imports = self._parse_external_maps(obj.get("imports", []))

        # Parse namespaceMap (NamespaceMap list)
        namespace_maps = self._parse_namespace_maps(obj.get("namespaceMap", []))

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
            namespaces=namespace_maps,
            imports=imports,
            context=context,
        )

    def _parse_attribution_text(self, obj: Dict[str, Any]) -> Optional[Union[str, Dict[str, Any]]]:
        """
        If the attribution text string can be parsed as JSON, return the resulting object (dict or list).
        Otherwise, return the original string. This accommodates tools that overload the
        attribution text fields with JSON objects.
        """
        attribution_text = self._get_optional(obj, "attributionText")

        if not attribution_text:
            return None

        try:
            return json.loads(attribution_text)
        except (json.JSONDecodeError, TypeError):
            return attribution_text

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
            package_version = self._get_optional(obj, "packageVersion")
            summary = self._get_optional(obj, "summary")
            description = self._get_optional(obj, "description")
            comment = self._get_optional(obj, "comment")
            download_location = self._get_optional(obj, "downloadLocation")
            concluded_license = self._parse_license(obj, "licenseConcluded")
            declared_license = self._parse_license(obj, "licenseDeclared")
            
            # Parse supplier and originator (if any)
            supplied_by = self._get_optional(obj, "supplier")
            originated_by = self._get_optional(obj, "originator")
            
            # Handle copyright text
            copyright_text = self._get_optional(obj, "software_copyrightText")
            
            # Handle creation info
            creation_info_ref = obj.get("creationInfo")
            creation_info = None
            if creation_info_ref:
                creation_info_obj = self._resolve_reference(creation_info_ref)
                if creation_info_obj:
                    creation_info = self._parse_creation_info(creation_info_obj)
            
            # Parse external references if present
            external_references = self._parse_external_references(obj.get("externalReference", []))
            # Parse external identifiers if present
            external_identifiers = self._parse_external_identifiers(obj.get("externalIdentifier", []))
            # Parse verifiedUsing (Hash/integrity method) if present
            verified_using_refs = self._get_list_field(obj, "verifiedUsing")
            verified_using = self._parse_integrity_methods(verified_using_refs)
            # Create and return the package
            return Package(
                spdx_id=spdx_id,
                name=name,
                package_version=package_version,
                summary=summary,
                description=description,
                comment=comment,
                download_location=download_location,
                supplied_by=supplied_by,
                originated_by=originated_by,
                copyright_text=copyright_text,
                creation_info=creation_info,
                primary_purpose=None,
                built_time=None,
                release_time=None,
                attribution_text=self._parse_attribution_text(obj),
                verified_using=verified_using,
                external_reference=external_references,
                external_identifier=external_identifiers,
                extension=None,
                concluded_license=concluded_license,
                declared_license=declared_license
            )
        except Exception as e:
            logger.warning(f"Error parsing Package: {str(e)}")
            return None

    def _parse_file_element(self, obj: Dict[str, Any]) -> Optional[File]:
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
            concluded_license = self._parse_license(obj, "licenseConcluded")
            declared_license = self._parse_license(obj, "licenseDeclared")
            
            # Parse hashes if present
            verified_using_refs = self._get_list_field(obj, "verifiedUsing")
            verified_using = self._parse_integrity_methods(verified_using_refs)
            
            # Handle creation info
            creation_info_ref = obj.get("creationInfo")
            creation_info = None
            if creation_info_ref:
                creation_info_obj = self._resolve_reference(creation_info_ref)
                if creation_info_obj:
                    creation_info = self._parse_creation_info(creation_info_obj)
            
            # Parse external references if present
            external_references = self._parse_external_references(obj.get("externalReference", []))
            # Parse external identifiers if present
            external_identifiers = self._parse_external_identifiers(obj.get("externalIdentifier", []))

            # Create and return the file
            return File(
                spdx_id=spdx_id,
                name=name,
                comment=comment,
                copyright_text=copyright_text,
                creation_info=creation_info,
                content_type=None,
                attribution_text=self._parse_attribution_text(obj),
                verified_using=verified_using,
                external_reference=external_references,
                external_identifier=external_identifiers,
                extension=None,
                concluded_license=concluded_license,
                declared_license=declared_license
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
            relationship_type_str = self._get_required(obj, "relationshipType")
            # Normalize to match enum: remove namespace, replace dashes/spaces, uppercase
            relationship_type_str = relationship_type_str.split(":")[-1]
            relationship_type_str = relationship_type_str.replace("-", "_").replace(" ", "_").upper()
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
            
            # Parse external references if present
            external_references = self._parse_external_references(obj.get("externalReference", []))
            # Parse external identifiers if present
            external_identifiers = self._parse_external_identifiers(obj.get("externalIdentifier", []))
            
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
                external_reference=external_references,
                external_identifier=external_identifiers,
            )
        except Exception as e:
            logger.warning(f"Error parsing Relationship: {str(e)}")
            return None

    def _parse_profile(self, obj) -> List[ProfileIdentifierType]:
        profile_config = obj.get('profile')
        if isinstance(profile_config, str):
            return [ProfileIdentifierType[profile_config]]

        # Assume multiple profiles are configured.
        return [ProfileIdentifierType[profile.upper()] for profile in sorted(profile_config)]

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
            profile = self._parse_profile(obj)
            spec_version = Version(obj.get("specVersion"))
            comment = obj.get("comment")
            
            # Parse datetime
            created = None
            if created_str:
                created = datetime.fromisoformat(created_str.replace('Z', '+00:00'))
            
            # Create and return CreationInfo
            return CreationInfo(
                spec_version=spec_version,
                created=created,
                created_by=created_by,
                profile=profile,
                created_using=created_using,
                comment=comment,
            )
        except Exception as e:
            logger.warning(f"Error parsing CreationInfo: {str(e)}")
            return None

    # Original entry point. Will replicate the bump from v2 workflow in this file.
    def check_spdx_document_validity(self, document: Dict[str, Any]) -> SpdxDocument:
        """
        Parse an SPDX v3 document dictionary into an SpdxDocument object.
        
        Args:
            document: The parsed JSON-LD document as a dictionary
            
        Returns:
            An SpdxDocument object
        """
        try:
            errors = self.validator.validate(document)
            if errors:
                error_msg = "\n".join(errors)
                raise ParserException(f"Invalid SPDX v3 document:\n{error_msg}")

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
            with open(file_path, 'r', encoding='utf-8') as f:
                document = json.load(f)
        except json.JSONDecodeError as e:
            raise ParserException(f"Invalid JSON in file {file_path}: {str(e)}")
        except FileNotFoundError:
            raise ParserException(f"File not found: {file_path}")
        
        if self.validate:
            self.check_spdx_document_validity(document)

        payload = Payload()
        self._parse_graph(document, payload)
        
        return payload
  
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
   
    def _parse_integrity_method(self, obj: dict):
        try:
            algorithm = obj.get("algorithm")
            hash_value = obj.get("hashValue")
            comment = obj.get("comment")
            # Map algorithm string to HashAlgorithm enum if possible
            if isinstance(algorithm, str):
                try:
                    algorithm_enum = HashAlgorithm[algorithm.upper()]
                except KeyError:
                    algorithm_enum = HashAlgorithm.OTHER
            else:
                algorithm_enum = algorithm
            return Hash(
                algorithm=algorithm_enum,
                hash_value=hash_value,
                comment=comment,
            )
        except Exception as e:
            logger.warning(f"Error parsing Hash (IntegrityMethod): {str(e)}")
            return None

    def _parse_integrity_methods(self, methods: list) -> list:
        """Parse a list of integrity methods, resolving references as needed."""
        return [self._parse_embedded_object(m, self._parse_integrity_method) for m in methods]
    
    def _parse_external_reference(self, obj: dict) -> Optional[ExternalReference]:
        """Parse a single ExternalReference object from JSON-LD."""
        from spdx_tools.spdx3.model.external_reference import ExternalReference, ExternalReferenceType
        try:
            # Type mapping: string to enum
            ext_ref_type_str = obj.get("externalReferenceType") or obj.get("external_reference_type")
            ext_ref_type = None
            if ext_ref_type_str:
                # Normalize to match enum: remove namespace, replace dashes/spaces, uppercase
                ext_ref_type_str = ext_ref_type_str.split(":")[-1]
                ext_ref_type_str = ext_ref_type_str.replace("-", "_").replace(" ", "_").upper()
                try:
                    ext_ref_type = ExternalReferenceType[ext_ref_type_str]
                except KeyError:
                    ext_ref_type = None
            locator = obj.get("locator")
            if locator is None:
                locator = []
            elif not isinstance(locator, list):
                locator = [locator]
            content_type = obj.get("contentType") or obj.get("content_type")
            comment = obj.get("comment")
            return ExternalReference(
                external_reference_type=ext_ref_type,
                locator=locator,
                content_type=content_type,
                comment=comment,
            )
        except Exception as e:
            logger.warning(f"Error parsing ExternalReference: {str(e)}")
            return None

    def _parse_external_references(self, references: list) -> List[ExternalReference]:
        """Parse a list of external references, resolving references as needed."""
        return [self._parse_embedded_object(r, self._parse_external_reference) for r in references]

    def _parse_embedded_object(self, obj, parse_func):
        """
        Helper for parsing embedded (non-top-level) SPDX objects.
        - obj: The JSON dict or reference to resolve.
        - parse_func: The function to parse the resolved object (e.g., self._parse_external_identifier).
        Returns the parsed object, or None if input is None.
        """
        if obj is None:
            return None
        resolved = self._resolve_reference(obj)
        return parse_func(resolved)

    def _parse_external_identifiers(self, identifiers: list) -> List[ExternalIdentifier]:
        """Parse a list of external identifiers, resolving references as needed."""
        return [self._parse_embedded_object(i, self._parse_external_identifier) for i in identifiers]
    
    def _parse_namespace_maps(self, namespaces: List[Dict[str, Any]]) -> List[NamespaceMap]:
        """Parse namespace maps from a list of dicts."""
        if not namespaces:
            return []
        result = []
        for ns in namespaces:
            # Accept both direct dicts and references
            ns_obj = self._resolve_reference(ns)
            if ns_obj is None:
                continue
            prefix = ns_obj.get("prefix")
            namespace = ns_obj.get("namespace")
            if prefix is not None and namespace is not None:
                result.append(NamespaceMap(prefix=prefix, namespace=namespace))
        return result
    
    def _parse_external_maps(self, maps: list) -> List[ExternalMap]:
        """Parse a list of external maps, resolving references as needed."""
        return [self._parse_embedded_object(m, self._parse_external_map) for m in maps]

    def _parse_external_map(self, obj: Dict[str, Any]) -> Optional[ExternalMap]:
        from spdx_tools.spdx3.model.external_map import ExternalMap
        try:
            external_id = obj.get("externalId") or obj.get("external_id")

            # Parse verifiedUsing (Hash/integrity method) if present
            verified_using_refs = self._get_list_field(obj, "verifiedUsing")
            verified_using = self._parse_integrity_methods(verified_using_refs)

            location_hint = obj.get("locationHint") or obj.get("location_hint")
            defining_document = obj.get("definingDocument") or obj.get("defining_document")

            return ExternalMap(
                external_id=external_id,
                verified_using=verified_using,
                location_hint=location_hint,
                defining_document=defining_document,
            )
        except Exception as e:
            logger.warning(f"Error parsing ExternalMap: {str(e)}")
            return None
    
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
                build_type = self._get_required(obj, "build_type")
                build_id = self._get_optional(obj, "buildId")
                comment = self._get_optional(obj, "comment")
                return SoftwareBuild(
                    spdx_id=spdx_id,
                    build_type=build_type,
                    build_id=build_id,
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
                attribution_text=self._parse_attribution_text(obj)
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
                from spdx_tools.spdx3.model.software import SoftwareDependencyRelationship
                spdx_id = self._get_required(obj, "spdxId")
                from_element = self._get_optional(obj, "from_element")
                relationship_type = self._get_optional(obj, "relationship_type")
                to = self._get_list_field(obj, "to", [])
                comment = self._get_optional(obj, "comment")
                return SoftwareDependencyRelationship(
                    spdx_id=spdx_id,
                    from_element=from_element,
                    relationship_type=relationship_type,
                    to=to,
                    comment=comment,
                )
            else:
                logger.warning(f"Unknown software extension type: {obj_type}")
                return None
        except Exception as e:
            logger.warning(f"Error parsing Software extension: {str(e)}")
            return None

    def _parse_external_identifier(self, obj: Dict[str, Any]):
        from spdx_tools.spdx3.model.external_identifier import ExternalIdentifier, ExternalIdentifierType

        try:
            extid_type_str = obj.get("externalIdentifierType") or obj.get("external_identifier_type")
            extid_type = None

            if extid_type_str:
                try:
                    extid_type = ExternalIdentifierType[extid_type_str.upper()]
                except Exception:
                    extid_type = ExternalIdentifierType.OTHER

            identifier = obj.get("identifier")
            comment = obj.get("comment")
            identifier_locator = obj.get("identifierLocator") or obj.get("identifier_locator") or []

            if not isinstance(identifier_locator, list):
                identifier_locator = [identifier_locator]
            issuing_authority = obj.get("issuingAuthority") or obj.get("issuing_authority")

            return ExternalIdentifier(
                external_identifier_type=extid_type,
                identifier=identifier,
                comment=comment,
                identifier_locator=identifier_locator,
                issuing_authority=issuing_authority,
            )
        except Exception as e:
            logger.warning(f"Error parsing ExternalIdentifier: {str(e)}")
            return None
