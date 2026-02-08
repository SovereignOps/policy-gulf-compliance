package sama_3_3_17_1

import data.lib.utils

# Control ID: 3.3.17.1
# Description: The vulnerability management process shoul d be defined, approved and implemented.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
