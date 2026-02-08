package sama_3_3_3_2

import data.lib.utils

# Control ID: 3.3.3.2
# Description: The effectiveness of the asset management process should be monitored, measured and periodically evaluated.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
