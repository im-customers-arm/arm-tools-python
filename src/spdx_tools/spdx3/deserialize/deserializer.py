# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json
import os
from pathlib import Path
from typing import Union, Dict, Any

from spdx_tools.spdx3.model import SpdxDocument
from spdx_tools.spdx3.parser.jsonld_parser import JSONLDV3Parser, ParserException

def parse_file(file_path: str, validate: bool = True) -> SpdxDocument:
    """
    Parse an SPDX v3 file into an SpdxDocument object.
    
    Args:
        file_path: Path to the file
        validate: Whether to validate the document against the schema
        
    Returns:
        An SpdxDocument object
    
    Raises:
        ParserException: If parsing fails
    """
    if not os.path.exists(file_path):
        raise ParserException(f"File not found: {file_path}")
    
    parser = JSONLDV3Parser(validate=validate)
    return parser.parse_file(file_path)

def parse_dict(data: Dict[str, Any], validate: bool = True) -> SpdxDocument:
    """
    Parse an SPDX v3 dictionary into an SpdxDocument object.
    
    Args:
        data: Dictionary representing an SPDX document
        validate: Whether to validate the document against the schema
        
    Returns:
        An SpdxDocument object
    """
    parser = JSONLDV3Parser(validate=validate)
    return parser.parse_document(data)

def parse_json_string(json_string: str, validate: bool = True) -> SpdxDocument:
    """
    Parse an SPDX v3 JSON string into an SpdxDocument object.
    
    Args:
        json_string: JSON string representing an SPDX document
        validate: Whether to validate the document against the schema
        
    Returns:
        An SpdxDocument object
    """
    parser = JSONLDV3Parser(validate=validate)
    return parser.parse_json_string(json_string)

def parse_anything(source: Union[str, Dict[str, Any], Path], validate: bool = True) -> SpdxDocument:
    """
    Parse an SPDX v3 document from various sources.
    
    Args:
        source: File path, JSON string, or dictionary
        validate: Whether to validate the document against the schema
        
    Returns:
        An SpdxDocument object
    """
    if isinstance(source, dict):
        return parse_dict(source, validate)
    
    if isinstance(source, Path):
        return parse_file(str(source), validate)
    
    if isinstance(source, str):
        if os.path.exists(source):
            return parse_file(source, validate)
        
        # Try parsing as a JSON string
        try:
            data = json.loads(source)
            return parse_dict(data, validate)
        except json.JSONDecodeError:
            raise ParserException("Source is neither a valid file path nor a valid JSON string")
    
    raise ParserException(f"Unsupported source type: {type(source)}")

