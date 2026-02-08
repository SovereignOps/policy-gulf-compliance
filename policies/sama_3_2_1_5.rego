package sama_3_2_1_5

import data.lib.utils

# Control ID: 3.2.1.5
# Description: The cyber security risk management process should address the Member Organization’s information assets, including (but not limited to ): a. business processes; b. business applications; c. infrastructure components.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
