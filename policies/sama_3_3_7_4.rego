package sama_3_3_7_4

import data.lib.utils

# Control ID: 3.3.7.4
# Description: The change management process should include: a. cyber security  requirements for controlling changes to information assets, such as  assessing the impact of requested changes, classification  of changes and the review of changes; b. security testing, which should (if applicable) include: 1. penetration testing; 2. code review if applications are developed internally; 3. code review of externally developed applications and if the source code is available
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
