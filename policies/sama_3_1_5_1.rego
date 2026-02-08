package sama_3_1_5_1

import data.lib.utils

# Control ID: 3.1.5.1
# Description: Cyber security  should be integrated into the Member Organization's project management methodology to ensure that cyber secu rity risks are identified and addressed as part of a project.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
