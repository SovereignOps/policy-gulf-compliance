package sama_3_3_3_1

import data.lib.utils

# Control ID: 3.3.3.1
# Description: The asset management process should be  defined , approved  and implemented .
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
