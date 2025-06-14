# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from beartype.typing import Any, Dict, List, Optional, Union

from spdx_tools.common.typing.dataclass_with_properties import dataclass_with_properties
from spdx_tools.common.typing.type_checks import check_types_and_set_values
from spdx_tools.spdx3.model import (
    Bundle,
    CreationInfo,
    ExternalIdentifier,
    ExternalMap,
    ExternalReference,
    IntegrityMethod,
    NamespaceMap,
)


@dataclass_with_properties
class SpdxDocument(Bundle):
    # The inherited field "name" is required for a SpdxDocument, no longer optional.
    # We overwrite the super-__init__ as check_types_and_set_values()
    # takes care of all fields (including inherited ones).
    def __init__(
        self,
        spdx_id: str,
        name: str,
        element: List[str],
        root_element: List[str],
        creation_info: Optional[CreationInfo] = None,
        summary: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        verified_using: List[IntegrityMethod] = None,
        external_reference: List[ExternalReference] = None,
        external_identifier: List[ExternalIdentifier] = None,
        extension: Optional[str] = None,
        namespaces: List[NamespaceMap] = None,
        imports: List[ExternalMap] = None,
        context: Optional[Union[str, Dict[str, Any]]] = None
    ):
        verified_using = [] if verified_using is None else verified_using
        external_reference = [] if external_reference is None else external_reference
        external_identifier = [] if external_identifier is None else external_identifier
        namespaces = [] if namespaces is None else namespaces
        imports = [] if imports is None else imports
        check_types_and_set_values(self, locals())

    def __eq__(self, other):
        if not isinstance(other, SpdxDocument):
            return False
        return (
            self.name == other.name and
            self.element == other.element and
            self.root_element == other.root_element and
            self.creation_info == other.creation_info and
            self.summary == other.summary and
            self.description == other.description and
            self.comment == other.comment and
            self.verified_using == other.verified_using and
            self.external_reference == other.external_reference and
            self.external_identifier == other.external_identifier and
            self.extension == other.extension and
            self.namespaces == other.namespaces and
            self.imports == other.imports and
            self.context == other.context
        )

    def __hash__(self):
        return hash((
            self.name,
            tuple(self.element),
            tuple(self.root_element),
            self.creation_info,
            self.summary,
            self.description,
            self.comment,
            tuple(self.verified_using),
            tuple(self.external_reference),
            tuple(self.external_identifier),
            self.extension,
            tuple(self.namespaces),
            tuple(self.imports),
            self.context
        ))
