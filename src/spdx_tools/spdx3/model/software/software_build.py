class SoftwareBuild:
    def __init__(self, spdx_id, build_id=None, build_system=None, comment=None):
        self.spdx_id = spdx_id
        self.build_id = build_id
        self.build_system = build_system
        self.comment = comment
