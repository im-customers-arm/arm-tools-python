# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from dataclasses import field
from datetime import datetime
from enum import Enum, auto

from beartype.typing import List, Optional

from spdx_tools.common.typing.dataclass_with_properties import dataclass_with_properties
from spdx_tools.common.typing.type_checks import check_types_and_set_values
from spdx_tools.spdx3.model import CreationInfo, Element, ExternalIdentifier, ExternalReference, IntegrityMethod


class RelationshipType(Enum):
    AFFECTS = auto()
    AMENDEDBY = auto()
    ANCESTOROF = auto()
    AVAILABLEFROM = auto()
    CONFIGURES = auto()
    CONTAINS = auto()
    COORDINATEDBY = auto()
    COPIEDTO = auto()
    DELEGATEDTO = auto()
    DEPENDSON = auto()
    DESCENDANTOF = auto()
    DESCRIBES = auto()
    DOESNOTAFFECT = auto()
    EXPANDSTO = auto()
    EXPLOITCREATEDBY = auto()
    FIXEDBY = auto()
    FIXEDIN = auto()
    FOUNDBY = auto()
    GENERATES = auto()
    HASADDEDFILE = auto()
    HASASSESSMENTFOR = auto()
    HASASSOCIATEDVULNERABILITY = auto()
    HASCONCLUDEDLICENSE = auto()
    HASDATAFILE = auto()
    HASDECLAREDLICENSE = auto()
    HASDELETEDFILE = auto()
    HASDEPENDENCYMANIFEST = auto()
    HASDISTRIBUTIONARTIFACT = auto()
    HASDOCUMENTATION = auto()
    HASDYNAMICLINK = auto()
    HASEVIDENCE = auto()
    HASEXAMPLE = auto()
    HASHOST = auto()
    HASINPUT = auto()
    HASMETADATA = auto()
    HASOPTIONALCOMPONENT = auto()
    HASOPTIONALDEPENDENCY = auto()
    HASOUTPUT = auto()
    HASPREREQUISITE = auto()
    HASPROVIDEDDEPENDENCY = auto()
    HASREQUIREMENT = auto()
    HASSPECIFICATION = auto()
    HASSTATICLINK = auto()
    HASTEST = auto()
    HASTESTCASE = auto()
    HASVARIANT = auto()
    INVOKEDBY = auto()
    MODIFIEDBY = auto()
    OTHER = auto()
    PACKAGEDBY = auto()
    PATCHEDBY = auto()
    PUBLISHEDBY = auto()
    REPORTEDBY = auto()
    REPUBLISHEDBY = auto()
    SERIALIZEDINARTIFACT = auto()
    TESTEDON = auto()
    TRAINEDON = auto()
    UNDERINVESTIGATIONFOR = auto()
    USESTOOL = auto()




class RelationshipCompleteness(Enum):
    INCOMPLETE = auto()
    COMPLETE = auto()
    NOASSERTION = auto()


@dataclass_with_properties
class Relationship(Element):
    # due to the inheritance we need to make all fields non-default in the __annotation__,
    # the __init__ method still raises an error if required fields are not set
    from_element: str = None
    to: List[str] = field(default_factory=list)
    relationship_type: RelationshipType = None
    completeness: Optional[RelationshipCompleteness] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None

    def __init__(
        self,
        spdx_id: str,
        from_element: str,
        relationship_type: RelationshipType,
        to: List[str] = None,
        creation_info: Optional[CreationInfo] = None,
        name: Optional[str] = None,
        summary: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        verified_using: List[IntegrityMethod] = None,
        external_reference: List[ExternalReference] = None,
        external_identifier: List[ExternalIdentifier] = None,
        extension: Optional[str] = None,
        completeness: Optional[RelationshipCompleteness] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
    ):
        to = [] if to is None else to
        verified_using = [] if verified_using is None else verified_using
        external_reference = [] if external_reference is None else external_reference
        external_identifier = [] if external_identifier is None else external_identifier
        check_types_and_set_values(self, locals())

    def __eq__(self, other):
        if not isinstance(other, Relationship):
            return False
        return (
            self.from_element == other.from_element and
            sorted(self.to) == sorted(other.to) and
            self.relationship_type == other.relationship_type and
            self.completeness == other.completeness and
            self.start_time == other.start_time and
            self.end_time == other.end_time and
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
            self.from_element,
            tuple(sorted(self.to)),
            self.relationship_type,
            self.completeness,
            self.start_time,
            self.end_time,
            self.creation_info,
            self.name,
            self.summary,
            self.description,
            self.comment,
            tuple(self.verified_using) if self.verified_using else (),
            tuple(self.external_reference) if self.external_reference else (),
            tuple(self.external_identifier) if self.external_identifier else (),
            self.extension
        ))
