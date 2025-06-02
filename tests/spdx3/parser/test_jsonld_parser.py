# SPDX-FileCopyrightText: 2025 spdx contributors
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime
import pytest
# import pdb; pdb.set_trace()
from spdx_tools.spdx3.model.dataset.dataset import DatasetType
from spdx_tools.spdx3.parser.jsonld_parser import JSONLDV3Parser, ParserException
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.model.software import SoftwarePurpose

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
                "@id": "SPDXRef-Licensing",
                "type": "Licensing",
                "spdxId": "SPDXRef-Licensing",
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
