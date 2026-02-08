package sama_3_2_1_2

import data.lib.utils

# Control ID: 3.2.1.2
# Description: The cyber security  risk management process should focus on safeguarding the confidentiality, integrity and availability of information assets.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
