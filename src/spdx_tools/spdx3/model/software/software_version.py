class SoftwareVersion:
    def __init__(self, spdx_id, version=None, comment=None):
        self.spdx_id = spdx_id
        self.version = version
        self.comment = comment

    def __eq__(self, other):
        if not isinstance(other, SoftwareVersion):
            return False
        return (
            self.version == other.version and
            self.comment == other.comment
        )

    def __hash__(self):
        return hash((
            self.version,
            self.comment
        ))
