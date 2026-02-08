package sama_3_3_8_3

import data.lib.utils

# Control ID: 3.3.8.3
# Description: The effectiveness of the infrastructure cyber  security  controls should be measured and periodically evaluated.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
