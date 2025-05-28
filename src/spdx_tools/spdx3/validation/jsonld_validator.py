# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
import json
import logging
import os
from pathlib import Path
from typing import Dict, List, Any, Optional, Union

import jsonschema

logger = logging.getLogger(__name__)

class JSONLDSchemaValidator:
    """Validator for SPDX v3 JSON-LD files using JSON Schema."""
    
    def __init__(self, schema_path: Optional[str] = None):
        """Initialize the validator with a schema file path."""
        if schema_path is None:
            # Use default schema included with the library
            schema_path = str(Path(__file__).parent.parent / "resources" / "schemas" / "spdx-v3.0.1-schema.json")
        
        if not os.path.exists(schema_path):
            raise FileNotFoundError(f"Schema file not found: {schema_path}")
        
        with open(schema_path, 'r') as schema_file:
            self.schema = json.load(schema_file)
    
    def validate(self, document: Dict[str, Any]) -> List[str]:
        """
        Validate an SPDX v3 document against the JSON schema.
        
        Args:
            document: The parsed JSON-LD document as a dictionary
            
        Returns:
            List of validation error messages or empty list if valid
        """
        validator = jsonschema.Draft7Validator(self.schema)
        errors = list(validator.iter_errors(document))
        
        error_messages = []
        for error in errors:
            path = "/".join(str(p) for p in error.path) if error.path else "root"
            message = f"{path}: {error.message}"
            error_messages.append(message)
            logger.warning(f"Validation error: {message}")
            
        return error_messages

    @classmethod
    def validate_file(cls, file_path: str) -> List[str]:
        """
        Validate an SPDX v3 JSON-LD file against the schema.
        
        Args:
            file_path: Path to the JSON-LD file
            
        Returns:
            List of validation error messages or empty list if valid
        """
        if not os.path.exists(file_path):
            return [f"File not found: {file_path}"]
        
        try:
            with open(file_path, 'r') as f:
                document = json.load(f)
        except json.JSONDecodeError as e:
            return [f"Invalid JSON: {str(e)}"]
        
        validator = cls()
        return validator.validate(document)

