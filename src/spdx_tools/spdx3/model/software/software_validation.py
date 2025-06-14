class SoftwareValidation:
    def __init__(self, spdx_id, validation_type=None, comment=None):
        self.spdx_id = spdx_id
        self.validation_type = validation_type
        self.comment = comment

    def __eq__(self, other):
        if not isinstance(other, SoftwareValidation):
            return False
        return (
            self.validation_type == other.validation_type and
            self.comment == other.comment
        )

    def __hash__(self):
        return hash((
            self.validation_type,
            self.comment
        ))
