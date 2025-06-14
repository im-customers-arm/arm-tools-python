# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from datetime import datetime

from beartype.typing import Any, Dict, List, Optional, Union

from spdx_tools.common.typing.dataclass_with_properties import dataclass_with_properties
from spdx_tools.common.typing.type_checks import check_types_and_set_values
from spdx_tools.spdx3.model import CreationInfo, ExternalIdentifier, ExternalReference, IntegrityMethod
from spdx_tools.spdx3.model.licensing import LicenseField
from spdx_tools.spdx3.model.software import SoftwarePurpose
from spdx_tools.spdx3.model.software.software_artifact import SoftwareArtifact


@dataclass_with_properties
class Package(SoftwareArtifact):
    package_version: Optional[str] = None
    download_location: Optional[str] = None  # anyURI
    package_url: Optional[str] = None  # anyURI
    homepage: Optional[str] = None  # anyURI
    source_info: Optional[str] = None

    def __init__(
        self,
        spdx_id: str,
        name: str,
        creation_info: Optional[CreationInfo] = None,
        summary: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        verified_using: List[IntegrityMethod] = None,
        external_reference: List[ExternalReference] = None,
        external_identifier: List[ExternalIdentifier] = None,
        extension: Optional[str] = None,
        originated_by: List[str] = None,
        supplied_by: List[str] = None,
        built_time: Optional[datetime] = None,
        release_time: Optional[datetime] = None,
        valid_until_time: Optional[datetime] = None,
        standard: List[str] = None,
        content_identifier: Optional[str] = None,
        primary_purpose: Optional[SoftwarePurpose] = None,
        additional_purpose: List[SoftwarePurpose] = None,
        concluded_license: Optional[LicenseField] = None,
        declared_license: Optional[LicenseField] = None,
        copyright_text: Optional[str] = None,
        attribution_text: Optional[Union[str, Dict[str, Any]]] = None,
        package_version: Optional[str] = None,
        download_location: Optional[str] = None,
        package_url: Optional[str] = None,
        homepage: Optional[str] = None,
        source_info: Optional[str] = None,
    ):
        verified_using = [] if verified_using is None else verified_using
        external_reference = [] if external_reference is None else external_reference
        external_identifier = [] if external_identifier is None else external_identifier
        originated_by = [] if originated_by is None else originated_by
        supplied_by = [] if supplied_by is None else supplied_by
        standard = [] if standard is None else standard
        additional_purpose = [] if additional_purpose is None else additional_purpose
        check_types_and_set_values(self, locals())

    def __eq__(self, other):
        if not isinstance(other, Package):
            return False
        return (
            self.package_version == other.package_version and
            self.download_location == other.download_location and
            self.package_url == other.package_url and
            self.homepage == other.homepage and
            self.source_info == other.source_info and
            self.creation_info == other.creation_info and
            self.name == other.name and
            self.summary == other.summary and
            self.description == other.description and
            self.comment == other.comment and
            self.verified_using == other.verified_using and
            self.external_reference == other.external_reference and
            self.external_identifier == other.external_identifier and
            self.extension == other.extension and
            self.originated_by == other.originated_by and
            self.supplied_by == other.supplied_by and
            self.built_time == other.built_time and
            self.release_time == other.release_time and
            self.valid_until_time == other.valid_until_time and
            self.standard == other.standard and
            self.content_identifier == other.content_identifier and
            self.primary_purpose == other.primary_purpose and
            self.additional_purpose == other.additional_purpose and
            self.concluded_license == other.concluded_license and
            self.declared_license == other.declared_license and
            self.copyright_text == other.copyright_text and
            self.attribution_text == other.attribution_text
        )

    def __hash__(self):
        return hash((
            self.package_version,
            self.download_location,
            self.package_url,
            self.homepage,
            self.source_info,
            self.creation_info,
            self.name,
            self.summary,
            self.description,
            self.comment,
            tuple(self.verified_using),
            tuple(self.external_reference),
            tuple(self.external_identifier),
            self.extension,
            tuple(self.originated_by),
            tuple(self.supplied_by),
            self.built_time,
            self.release_time,
            self.valid_until_time,
            tuple(self.standard),
            self.content_identifier,
            self.primary_purpose,
            tuple(self.additional_purpose),
            self.concluded_license,
            self.declared_license,
            self.copyright_text,
            self.attribution_text
        ))
