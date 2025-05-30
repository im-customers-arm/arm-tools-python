# SPDX-FileCopyrightText: 2023 spdx contributors
#
# SPDX-License-Identifier: Apache-2.0

class SoftwareRelease:
    def __init__(self, spdx_id, release_time=None, comment=None):
        self.spdx_id = spdx_id
        self.release_time = release_time
        self.comment = comment
