# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0

class SoftwareRelease:
    def __init__(self, spdx_id, release_time=None, comment=None):
        self.spdx_id = spdx_id
        self.release_time = release_time
        self.comment = comment

    def __eq__(self, other):
        if not isinstance(other, SoftwareRelease):
            return False
        return (
            self.release_time == other.release_time and
            self.comment == other.comment
        )

    def __hash__(self):
        return hash((
            self.release_time,
            self.comment
        ))
