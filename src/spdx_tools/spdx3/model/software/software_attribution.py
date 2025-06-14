class SoftwareAttribution:
    def __init__(self, spdx_id, attribution_text=None, comment=None):
        self.spdx_id = spdx_id
        self.attribution_text = attribution_text
        self.comment = comment

    def __eq__(self, other):
        if not isinstance(other, SoftwareAttribution):
            return False
        return (
            self.attribution_text == other.attribution_text and
            self.comment == other.comment
        )

    def __hash__(self):
        return hash((
            self.attribution_text,
            self.comment
        ))
