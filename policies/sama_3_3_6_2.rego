package sama_3_3_6_2

import data.lib.utils

# Control ID: 3.3.6.2
# Description: The compliance with the application security standards should be monitore d.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
