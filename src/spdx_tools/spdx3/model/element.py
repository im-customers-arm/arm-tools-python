# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from abc import ABC, abstractmethod
from dataclasses import field

from beartype.typing import List, Optional

from spdx_tools.common.typing.dataclass_with_properties import dataclass_with_properties
from spdx_tools.spdx3.model import CreationInfo, ExternalIdentifier, ExternalReference, IntegrityMethod


@dataclass_with_properties
class Element(ABC):
    spdx_id: str  # IRI
    creation_info: Optional[CreationInfo] = None
    name: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    comment: Optional[str] = None
    verified_using: List[IntegrityMethod] = field(default_factory=list)
    external_reference: List[ExternalReference] = field(default_factory=list)
    external_identifier: List[ExternalIdentifier] = field(default_factory=list)
    extension: Optional[str] = None  # placeholder for extension

    @abstractmethod
    def __init__(self):
        pass

    def __eq__(self, other):
        if not isinstance(other, Element):
            return False
        return (
            self.creation_info == other.creation_info and
            self.name == other.name and
            self.summary == other.summary and
            self.description == other.description and
            self.comment == other.comment and
            self.verified_using == other.verified_using and
            self.external_reference == other.external_reference and
            self.external_identifier == other.external_identifier and
            self.extension == other.extension
        )

    def __hash__(self):
        return hash((
            self.creation_info,
            self.name,
            self.summary,
            self.description,
            self.comment,
            tuple(self.verified_using),
            tuple(self.external_reference),
            tuple(self.external_identifier),
            self.extension
        ))
