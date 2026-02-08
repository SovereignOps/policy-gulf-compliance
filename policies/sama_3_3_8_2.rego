package sama_3_3_8_2

import data.lib.utils

# Control ID: 3.3.8.2
# Description: The compliance with the infrastructure security  standards should be monitored .
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
