class SoftwareBuild:
    def __init__(self, spdx_id, build_id=None, build_system=None, comment=None):
        self.spdx_id = spdx_id
        self.build_id = build_id
        self.build_system = build_system
        self.comment = comment

    def __eq__(self, other):
        if not isinstance(other, SoftwareBuild):
            return False
        return (
            self.build_id == other.build_id and
            self.build_system == other.build_system and
            self.comment == other.comment
        )

    def __hash__(self):
        return hash((
            self.build_id,
            self.build_system,
            self.comment
        ))
