package sama_3_3_2_2

import data.lib.utils

# Control ID: 3.3.2.2
# Description: The effectiveness of the physical security process should be monitored, measured and periodically evalua ted.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
