# SPDX-FileCopyrightText: 2025 spdx contributors
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
import pytest
# import pdb; pdb.set_trace()

from semantic_version import Version
from spdx_tools.spdx3.model.dataset.dataset import DatasetType
from spdx_tools.spdx3.model.profile_identifier import ProfileIdentifierType
from spdx_tools.spdx3.parser.jsonld_parser import JSONLDV3Parser, ParserException
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.model.software import SoftwarePurpose
from spdx_tools.spdx3.model.relationship import RelationshipType

# Minimal valid SPDX v3 JSON-LD document for testing
def minimal_spdx_v3_doc():
    return {
        "@graph": [
            {
                "@id": "SPDXRef-DOCUMENT",
                "type": "SpdxDocument",
                "spdxId": "SPDXRef-DOCUMENT",
                "name": "Test Document"
            }
        ]
    }

def test_parse_minimal_document():
    parser = JSONLDV3Parser(validate=False)
    doc = minimal_spdx_v3_doc()
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert len(entries) == 1
    assert entries["SPDXRef-DOCUMENT"].name == "Test Document"

def test_parse_file_not_found(tmp_path):
    parser = JSONLDV3Parser(validate=False)
    missing_file = tmp_path / "does_not_exist.jsonld"
    with pytest.raises(ParserException) as excinfo:
        parser.parse_file(str(missing_file))
    assert "File not found" in str(excinfo.value)

def test_parse_invalid_json(tmp_path):
    parser = JSONLDV3Parser(validate=False)
    bad_file = tmp_path / "bad.jsonld"
    bad_file.write_text("{ invalid json }", encoding="utf-8")
    with pytest.raises(ParserException) as excinfo:
        parser.parse_file(str(bad_file))
    assert "Invalid JSON" in str(excinfo.value)

def test_missing_required_field():
    parser = JSONLDV3Parser(validate=False)
    doc = {"@graph": [{"type": "SpdxDocument", "name": "No ID"}]}
    payload = Payload()
    with pytest.raises(KeyError):
        parser._parse_graph(doc, payload)

def test_parse_document_with_package():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-DOCUMENT",
                "type": "SpdxDocument",
                "spdxId": "SPDXRef-DOCUMENT",
                "name": "Test Document"
            },
            {
                "@id": "SPDXRef-Package",
                "type": "Package",
                "spdxId": "SPDXRef-Package",
                "name": "Test Package"
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Package" in entries
    assert entries["SPDXRef-Package"].name == "Test Package"


def test_parse_document_with_package_creation_info():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-DOCUMENT",
                "type": "SpdxDocument",
                "spdxId": "SPDXRef-DOCUMENT",
                "name": "Test Document"
            },
            {
                "@id": "SPDXRef-Package",
                "type": "Package",
                "spdxId": "SPDXRef-Package",
                "name": "Test Package",
                "creationInfo": "SPDXRef-CreationInfo"
            },
            {
                "@id": "SPDXRef-CreationInfo",
                "type": "CreationInfo",
                "spdxId": "SPDXRef-CreationInfo",
                "created": "20250401",
                "createdBy": ["Acme Corp"],
                "profile": "BUILD",
                "createdUsing": ["Some SBOM Generator"],
                "comment":"This represents a creation info element",
                "specVersion": "3.0.1"
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    creation_info = entries["SPDXRef-Package"].creation_info
    assert creation_info.data_license == "CC0-1.0"
    assert creation_info.created == datetime(2025, 4, 1)
    assert creation_info.created_by == ["Acme Corp"]
    assert creation_info.profile == [ProfileIdentifierType.BUILD]
    assert creation_info.created_using == ["Some SBOM Generator"]
    assert creation_info.comment == "This represents a creation info element"
    assert creation_info.spec_version == Version("3.0.1")
    
def test_parse_creation_info_multiple_profiles():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-DOCUMENT",
                "type": "SpdxDocument",
                "spdxId": "SPDXRef-DOCUMENT",
                "name": "Test Document"
            },
            {
                "@id": "SPDXRef-Package",
                "type": "Package",
                "spdxId": "SPDXRef-Package",
                "name": "Test Package",
                "creationInfo": "SPDXRef-CreationInfo"
            },
            {
                "@id": "SPDXRef-CreationInfo",
                "type": "CreationInfo",
                "spdxId": "SPDXRef-CreationInfo",
                "created": "20250401",
                "createdBy": ["Acme Corp"],
                # Multiple profiles may be configured.
                "profile": [
                    "EXTENSION",
                    "SOFTWARE",
                    "USAGE",
                    "LICENSING",
                    "SECURITY",
                    "DATASET",
                    "CORE",
                    "BUILD",
                    "AI",
                ],              
                "createdUsing": ["Some SBOM Generator"],
                "comment":"This represents a creation info element",
                "specVersion": "3.0.1"
            }
        ]
    }

    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    creation_info = entries["SPDXRef-Package"].creation_info
    print(creation_info.profile)
    actual_profile_names = [p.name for p in creation_info.profile]
    expected_profile_names = [
        ProfileIdentifierType.AI.name,
        ProfileIdentifierType.BUILD.name,
        ProfileIdentifierType.CORE.name,
        ProfileIdentifierType.DATASET.name,
        ProfileIdentifierType.EXTENSION.name,
        ProfileIdentifierType.LICENSING.name,
        ProfileIdentifierType.SECURITY.name,
        ProfileIdentifierType.SOFTWARE.name,
        ProfileIdentifierType.USAGE.name,
    ]

    assert actual_profile_names == expected_profile_names

def test_parse_document_with_relationship():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-DOCUMENT",
                "type": "SpdxDocument",
                "spdxId": "SPDXRef-DOCUMENT",
                "name": "Test Document"
            },
            {
                "@id": "SPDXRef-Rel",
                "type": "Relationship",
                "spdxId": "SPDXRef-Rel",
                "from": "SPDXRef-DOCUMENT",
                "to": ["SPDXRef-Other"],
                "relationshipType": "DESCRIBES"
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Rel" in entries
    assert entries["SPDXRef-Rel"].relationship_type.name == "DESCRIBES"

def test_parse_document_with_build_extension():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-Build",
                "type": "Build",
                "spdxId": "SPDXRef-Build",
                "name": "Build Example",
                "build_type": "test_build"
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Build" in entries
    assert getattr(entries["SPDXRef-Build"], "name", None) == "Build Example"

def test_reference_resolution():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-DOCUMENT",
                "type": "SpdxDocument",
                "spdxId": "SPDXRef-DOCUMENT",
                "name": "Test Document",
                "creationInfo": "SPDXRef-CreationInfo"
            },
            {
                "@id": "SPDXRef-CreationInfo",
                "type": "CreationInfo",
                "created": "2025-01-01T00:00:00Z"
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-DOCUMENT" in entries
    # You can add more assertions if your parser attaches creationInfo

def test_unknown_type_handling():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-Unknown",
                "type": "UnknownType",
                "spdxId": "SPDXRef-Unknown",
                "name": "Unknown"
            }
        ]
    }
    payload = Payload()
    # Should not raise
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Unknown" not in entries or entries["SPDXRef-Unknown"] is not None

def test_parse_document_with_ai_extension():
    parser = JSONLDV3Parser(validate=False)
    hyperparameters = {"foo": "bar"}
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-AI",
                "type": "AI",
                "spdxId": "SPDXRef-AI",
                "name": "AI Example",
                "hyperparameter": hyperparameters
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-AI" in entries
    assert getattr(entries["SPDXRef-AI"], "name", None) == "AI Example"
    assert getattr(entries["SPDXRef-AI"], "hyperparameter", None) == hyperparameters

def test_parse_document_with_dataset_extension():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-Dataset",
                "type": "Dataset",
                "spdxId": "SPDXRef-Dataset",
                "name": "Dataset Example",
                "originator": ["Some team"],
                "downloadLocation": "/c/users/owner/downloads",
                "primaryPurpose": SoftwarePurpose.DATA,
                "builtTime": datetime(2025, 4, 1, 12, 0),
                "releaseTime": datetime(2025, 6, 2, 12, 0),
                "datasetType": [DatasetType.IMAGE],
                "datasetFormat": "JPEG",
                "datasetSize": 1000,
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Dataset" in entries
    assert getattr(entries["SPDXRef-Dataset"], "name", None) == "Dataset Example"
    assert getattr(entries["SPDXRef-Dataset"], "dataset_type", None) == [DatasetType.IMAGE]
    assert getattr(entries["SPDXRef-Dataset"], "dataset_size", None) == 1000

def test_parse_document_with_licensing_extension():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "LicenseRef-Licensing",
                "type": "Licensing",
                "licenseId": "MIT",
                "name": "Licensing Example",
                "licenseText": "Permission is hereby granted to any licensee..."
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Licensing" in entries
    assert getattr(entries["SPDXRef-Licensing"], "spdx_id", None) == "SPDXRef-Licensing"
    assert getattr(entries["SPDXRef-Licensing"], "license_name", None) == "Licensing Example"
    assert getattr(entries["SPDXRef-Licensing"], "license_text", None) == "Permission is hereby granted to any licensee..."

def test_parse_document_with_software_release_extension():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-Release",
                "type": "SoftwareRelease",
                "spdxId": "SPDXRef-Release",
                "releaseTime": "2025-05-30T12:00:00Z",
                "comment": "Release comment"
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Release" in entries
    assert getattr(entries["SPDXRef-Release"], "spdx_id", None) == "SPDXRef-Release"
    assert getattr(entries["SPDXRef-Release"], "release_time", None) == "2025-05-30T12:00:00Z"
    assert getattr(entries["SPDXRef-Release"], "comment", None) == "Release comment"

def test_parse_document_with_software_dependency_extension():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-Dep",
                "type": "SoftwareDependency",
                "spdxId": "SPDXRef-Dep",
                "from_element": "SPDXRef-DOCUMENT",
                "relationship_type": RelationshipType.DEPENDSON,
                "to": ["SPDXRef-Other"],
                "comment": "Dependency comment"
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Dep" in entries
    assert getattr(entries["SPDXRef-Dep"], "from_element", None) == "SPDXRef-DOCUMENT"
    assert getattr(entries["SPDXRef-Dep"], "relationship_type", None) == RelationshipType.DEPENDSON
    assert getattr(entries["SPDXRef-Dep"], "to", None) == ["SPDXRef-Other"]
    assert getattr(entries["SPDXRef-Dep"], "comment", None) == "Dependency comment"

def test_parse_external_identifier():
    parser = JSONLDV3Parser(validate=False)
    # ExternalIdentifier embedded in a Package
    EXTERNAL_IDENTIFIER_JSONLD = {
        "externalIdentifierType": "CPE23",
        "identifier": "cpe:2.3:a:example:example:1.0.0:*:*:*:*:*:*:*",
        "comment": "CPE identifier for this package",
        "identifierLocator": ["https://cpe.example.com/lookup"],
        "issuingAuthority": "https://cpe.example.com/"
    }
    document = {
        "@graph": [
            {
                "@id": "SPDXRef-Package",
                "type": "Package",
                "spdxId": "SPDXRef-Package",
                "name": "Test Package",
                "externalIdentifier": [EXTERNAL_IDENTIFIER_JSONLD]
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(document, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Package" in entries
    package = entries["SPDXRef-Package"]
    external_identifier_list = package.external_identifier
    from spdx_tools.spdx3.model.external_identifier import ExternalIdentifierType
    assert len(external_identifier_list) == 1
    extid = external_identifier_list[0]
    assert extid.external_identifier_type == ExternalIdentifierType.CPE23
    assert extid.identifier == "cpe:2.3:a:example:example:1.0.0:*:*:*:*:*:*:*"
    assert extid.comment == "CPE identifier for this package"
    assert extid.identifier_locator == ["https://cpe.example.com/lookup"]
    assert extid.issuing_authority == "https://cpe.example.com/"

def test_parse_document_with_imports():
    parser = JSONLDV3Parser(validate=False)
    EXTERNAL_MAP_JSONLD = {
        "externalId": "pkg:pypi/example@1.0.0",
    }

    document = {
        "@graph": [
            {
                "@id": "SPDXRef-DOCUMENT",
                "type": "SpdxDocument",
                "spdxId": "SPDXRef-DOCUMENT",
                "name": "Test Document",
                "imports": [EXTERNAL_MAP_JSONLD]
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(document, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-DOCUMENT" in entries

    doc = entries["SPDXRef-DOCUMENT"]
    imports = doc.imports

    from spdx_tools.spdx3.model.external_map import ExternalMap
    assert isinstance(imports, list)
    assert len(imports) == 1
    external_map = imports[0]
    assert isinstance(external_map, ExternalMap)
    assert external_map.external_id == "pkg:pypi/example@1.0.0"

def test_parse_external_reference():
    parser = JSONLDV3Parser(validate=False)
    # ExternalReference embedded in a Package
    EXTERNAL_REFERENCE_JSONLD = {
        "externalReferenceType": "OTHER",
        "locator": ["org.apache.tomcat:tomcat:9.0.0.M4"],
        "contentType": "externalReferenceContentType",
        "comment": "externalReferenceComment"
    }
    document = {
        "@graph": [
            {
                "@id": "SPDXRef-Package",
                "type": "Package",
                "spdxId": "SPDXRef-Package",
                "name": "Test Package",
                "externalReference": [EXTERNAL_REFERENCE_JSONLD]
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(document, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Package" in entries
    package = entries["SPDXRef-Package"]
    external_reference_list = package.external_reference
    
    from spdx_tools.spdx3.model.external_reference import ExternalReferenceType
    
    assert len(external_reference_list) == 1
    external_reference = external_reference_list[0]
    assert external_reference.external_reference_type == ExternalReferenceType.OTHER
    assert external_reference.locator == ["org.apache.tomcat:tomcat:9.0.0.M4"]
    assert external_reference.content_type == "externalReferenceContentType"
    assert external_reference.comment == "externalReferenceComment"

def test_parse_file_with_integrity_method():
    parser = JSONLDV3Parser(validate=False)
    # IntegrityMethod embedded in a File
    INTEGRITY_METHOD_JSONLD = {
        "algorithm": "SHA1",
        "hashValue": "71c4025dd9897b364f3ebbb42c484ff43d00791c",
        "comment": "hashComment"
    }
    document = {
        "@graph": [
            {
                "@id": "SPDXRef-File",
                "type": "File",
                "spdxId": "SPDXRef-File",
                "name": "Test File",
                "verifiedUsing": [INTEGRITY_METHOD_JSONLD]
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(document, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-File" in entries
    file = entries["SPDXRef-File"]
    verified_using_list = file.verified_using
    from spdx_tools.spdx3.model.integrity_method import IntegrityMethod
    assert isinstance(verified_using_list, list)
    assert len(verified_using_list) == 1
    integrity_method = verified_using_list[0]
    assert isinstance(integrity_method, IntegrityMethod)
    assert integrity_method.algorithm.name == "SHA1"
    assert integrity_method.hash_value == "71c4025dd9897b364f3ebbb42c484ff43d00791c"
    assert integrity_method.comment == "hashComment"

def test_parse_package_with_integrity_method():
    parser = JSONLDV3Parser(validate=False)
    # Hash/IntegrityMethod embedded in a Package
    INTEGRITY_METHOD_JSONLD = {
        "algorithm": "SHA256",
        "hashValue": "abcdef1234567890",
        "comment": "package hash"
    }
    document = {
        "@graph": [
            {
                "@id": "SPDXRef-Package",
                "type": "Package",
                "spdxId": "SPDXRef-Package",
                "name": "Test Package",
                "verifiedUsing": [INTEGRITY_METHOD_JSONLD]
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(document, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-Package" in entries
    package = entries["SPDXRef-Package"]
    verified_using_list = package.verified_using
    from spdx_tools.spdx3.model.hash import Hash
    assert isinstance(verified_using_list, list)
    assert len(verified_using_list) == 1
    integrity_method = verified_using_list[0]
    assert isinstance(integrity_method, Hash)
    assert integrity_method.algorithm.name == "SHA256"
    assert integrity_method.hash_value == "abcdef1234567890"
    assert integrity_method.comment == "package hash"

def test_parse_external_map_with_integrity_method():
    parser = JSONLDV3Parser(validate=False)
    # Hash/IntegrityMethod embedded in an ExternalMap
    INTEGRITY_METHOD_JSONLD = {
        "algorithm": "SHA512",
        "hashValue": "1234deadbeef5678",
        "comment": "external map hash"
    }
    EXTERNAL_MAP_JSONLD = {
        "externalId": "pkg:deb/debian/curl@7.50.3-1?arch=i386",
        "verifiedUsing": [INTEGRITY_METHOD_JSONLD]
    }
    document = {
        "@graph": [
            {
                "@id": "SPDXRef-DOCUMENT",
                "type": "SpdxDocument",
                "spdxId": "SPDXRef-DOCUMENT",
                "name": "Test Document",
                "imports": [EXTERNAL_MAP_JSONLD]
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(document, payload)
    entries = payload.get_full_map()
    assert "SPDXRef-DOCUMENT" in entries
    doc = entries["SPDXRef-DOCUMENT"]
    imports = doc.imports
    from spdx_tools.spdx3.model.external_map import ExternalMap
    from spdx_tools.spdx3.model.hash import Hash
    assert isinstance(imports, list)
    assert len(imports) == 1
    external_map = imports[0]
    assert isinstance(external_map, ExternalMap)
    assert external_map.external_id == "pkg:deb/debian/curl@7.50.3-1?arch=i386"
    verified_using_list = external_map.verified_using
    assert isinstance(verified_using_list, list)
    assert len(verified_using_list) == 1
    hash_obj = verified_using_list[0]
    assert isinstance(hash_obj, Hash)
    assert hash_obj.algorithm.name == "SHA512"
    assert hash_obj.hash_value == "1234deadbeef5678"
    assert hash_obj.comment == "external map hash"

def test_parse_document_with_namespace_map():
    parser = JSONLDV3Parser(validate=False)
    doc = {
        "@graph": [
            {
                "@id": "SPDXRef-DOCUMENT",
                "type": "SpdxDocument",
                "spdxId": "SPDXRef-DOCUMENT",
                "name": "Test Document",
                "namespaceMap": [
                    {"prefix": "ex", "namespace": "https://example.com/ns#"},
                    {"prefix": "foo", "namespace": "https://foo.org/ns#"}
                ]
            }
        ]
    }
    payload = Payload()
    parser._parse_graph(doc, payload)
    entries = payload.get_full_map()
    doc_obj = entries["SPDXRef-DOCUMENT"]
    assert hasattr(doc_obj, "namespaces")
    assert len(doc_obj.namespaces) == 2
    assert doc_obj.namespaces[0].prefix == "ex"
    assert doc_obj.namespaces[0].namespace == "https://example.com/ns#"
    assert doc_obj.namespaces[1].prefix == "foo"
    assert doc_obj.namespaces[1].namespace == "https://foo.org/ns#"
