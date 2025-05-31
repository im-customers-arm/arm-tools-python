# SPDX-FileCopyrightText: 2025 spdx contributors
# SPDX-License-Identifier: Apache-2.0
import pytest
# import pdb; pdb.set_trace()
from spdx_tools.spdx3.parser.jsonld_parser import JSONLDV3Parser, ParserException
from spdx_tools.spdx3.payload import Payload

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
