package sama_3_3_13_2

import data.lib.utils

# Control ID: 3.3.13.2
# Description: The compliance with cyber security  standards for electronic banking services should be monitored .
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
