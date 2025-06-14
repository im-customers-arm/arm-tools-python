# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0
from dataclasses import field
from datetime import datetime
from enum import Enum, auto

from beartype.typing import Dict, List, Optional

from spdx_tools.common.typing.dataclass_with_properties import dataclass_with_properties
from spdx_tools.common.typing.type_checks import check_types_and_set_values
from spdx_tools.spdx3.model import CreationInfo, ExternalIdentifier, ExternalReference, IntegrityMethod
from spdx_tools.spdx3.model.licensing import LicenseField
from spdx_tools.spdx3.model.software import Package, SoftwarePurpose


class DatasetType(Enum):
    STRUCTURED = auto()
    NUMERIC = auto()
    TEXT = auto()
    CATEGORICAL = auto()
    GRAPH = auto()
    TIMESERIES = auto()
    TIMESTAMP = auto()
    SENSOR = auto()
    IMAGE = auto()
    SYNTACTIC = auto()
    AUDIO = auto()
    VIDEO = auto()
    OTHER = auto()
    NO_ASSERTION = auto()


class ConfidentialityLevelType(Enum):
    RED = auto()
    AMBER = auto()
    GREEN = auto()
    CLEAR = auto()


class DatasetAvailabilityType(Enum):
    DIRECT_DOWNLOAD = auto()
    SCRAPING_SCRIPT = auto()
    QUERY = auto()
    CLICKTHROUGH = auto()
    REGISTRATION = auto()


@dataclass_with_properties
class Dataset(Package):
    dataset_type: List[DatasetType] = None
    data_collection_process: Optional[str] = None
    intended_use: Optional[str] = None
    dataset_size: Optional[int] = None
    dataset_noise: Optional[str] = None
    data_preprocessing: List[str] = field(default_factory=list)
    sensor: Dict[str, Optional[str]] = field(default_factory=dict)
    known_bias: List[str] = field(default_factory=list)
    sensitive_personal_information: Optional[bool] = None
    anonymization_method_used: List[str] = field(default_factory=list)
    confidentiality_level: Optional[ConfidentialityLevelType] = None
    dataset_update_mechanism: Optional[str] = None
    dataset_availability: Optional[DatasetAvailabilityType] = None

    def __init__(
        self,
        spdx_id: str,
        name: str,
        originated_by: List[str],
        download_location: str,
        primary_purpose: SoftwarePurpose,
        built_time: datetime,
        release_time: datetime,
        dataset_type: List[DatasetType],
        creation_info: Optional[CreationInfo] = None,
        summary: Optional[str] = None,
        description: Optional[str] = None,
        comment: Optional[str] = None,
        verified_using: List[IntegrityMethod] = None,
        external_reference: List[ExternalReference] = None,
        external_identifier: List[ExternalIdentifier] = None,
        extension: Optional[str] = None,
        supplied_by: List[str] = None,
        valid_until_time: Optional[datetime] = None,
        standard: List[str] = None,
        content_identifier: Optional[str] = None,
        additional_purpose: List[SoftwarePurpose] = None,
        concluded_license: Optional[LicenseField] = None,
        declared_license: Optional[LicenseField] = None,
        copyright_text: Optional[str] = None,
        attribution_text: Optional[str] = None,
        package_version: Optional[str] = None,
        package_url: Optional[str] = None,
        homepage: Optional[str] = None,
        source_info: Optional[str] = None,
        data_collection_process: Optional[str] = None,
        intended_use: Optional[str] = None,
        dataset_size: Optional[int] = None,
        dataset_noise: Optional[str] = None,
        data_preprocessing: List[str] = None,
        sensor: Dict[str, Optional[str]] = None,
        known_bias: List[str] = None,
        sensitive_personal_information: Optional[bool] = None,
        anonymization_method_used: List[str] = None,
        confidentiality_level: Optional[ConfidentialityLevelType] = None,
        dataset_update_mechanism: Optional[str] = None,
        dataset_availability: Optional[DatasetAvailabilityType] = None,
    ):
        verified_using = [] if verified_using is None else verified_using
        external_reference = [] if external_reference is None else external_reference
        external_identifier = [] if external_identifier is None else external_identifier
        originated_by = [] if originated_by is None else originated_by
        additional_purpose = [] if additional_purpose is None else additional_purpose
        supplied_by = [] if supplied_by is None else supplied_by
        standard = [] if standard is None else standard
        data_preprocessing = [] if data_preprocessing is None else data_preprocessing
        sensor = {} if sensor is None else sensor
        known_bias = [] if known_bias is None else known_bias
        anonymization_method_used = [] if anonymization_method_used is None else anonymization_method_used
        check_types_and_set_values(self, locals())

    def __eq__(self, other):
        if not isinstance(other, Dataset):
            return False
        return (
            self.name == other.name and
            self.originated_by == other.originated_by and
            self.download_location == other.download_location and
            self.primary_purpose == other.primary_purpose and
            self.built_time == other.built_time and
            self.release_time == other.release_time and
            self.dataset_type == other.dataset_type and
            self.creation_info == other.creation_info and
            self.summary == other.summary and
            self.description == other.description and
            self.comment == other.comment and
            self.verified_using == other.verified_using and
            self.external_reference == other.external_reference and
            self.external_identifier == other.external_identifier and
            self.extension == other.extension and
            self.supplied_by == other.supplied_by and
            self.valid_until_time == other.valid_until_time and
            self.standard == other.standard and
            self.content_identifier == other.content_identifier and
            self.additional_purpose == other.additional_purpose and
            self.concluded_license == other.concluded_license and
            self.declared_license == other.declared_license and
            self.copyright_text == other.copyright_text and
            self.attribution_text == other.attribution_text and
            self.package_version == other.package_version and
            self.package_url == other.package_url and
            self.homepage == other.homepage and
            self.source_info == other.source_info and
            self.data_collection_process == other.data_collection_process and
            self.intended_use == other.intended_use and
            self.dataset_size == other.dataset_size and
            self.dataset_noise == other.dataset_noise and
            self.data_preprocessing == other.data_preprocessing and
            self.sensor == other.sensor and
            self.known_bias == other.known_bias and
            self.sensitive_personal_information == other.sensitive_personal_information and
            self.anonymization_method_used == other.anonymization_method_used and
            self.confidentiality_level == other.confidentiality_level and
            self.dataset_update_mechanism == other.dataset_update_mechanism and
            self.dataset_availability == other.dataset_availability
        )

    def __hash__(self):
        return hash((
            self.name,
            tuple(self.originated_by),
            self.download_location,
            self.primary_purpose,
            self.built_time,
            self.release_time,
            tuple(self.dataset_type),
            self.creation_info,
            self.summary,
            self.description,
            self.comment,
            tuple(self.verified_using),
            tuple(self.external_reference),
            tuple(self.external_identifier),
            self.extension,
            tuple(self.supplied_by) if self.supplied_by is not None else None,
            self.valid_until_time,
            tuple(self.standard) if self.standard is not None else None,
            self.content_identifier,
            tuple(self.additional_purpose) if self.additional_purpose is not None else None,
            self.concluded_license,
            self.declared_license,
            self.copyright_text,
            self.attribution_text,
            self.package_version,
            self.package_url,
            self.homepage,
            self.source_info,
            self.data_collection_process,
            self.intended_use,
            self.dataset_size,
            self.dataset_noise,
            tuple(self.data_preprocessing),
            frozenset(self.sensor.items()),
            tuple(self.known_bias),
            self.sensitive_personal_information,
            tuple(self.anonymization_method_used),
            self.confidentiality_level,
            self.dataset_update_mechanism,
            self.dataset_availability
        ))
