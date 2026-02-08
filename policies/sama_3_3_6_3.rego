package sama_3_3_6_3

import data.lib.utils

# Control ID: 3.3.6.3
# Description: The effectiveness of the application cyber security  controls should be measured and periodically evaluated.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
