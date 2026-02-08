package sama_3_1_1_3

import data.lib.utils

# Control ID: 3.1.1.3
# Description: The following positions should be represented in the cyber security committee: a. senior managers from all relevant departments (e.g., COO, CIO, compliance officer, heads of relevant busine ss departments); b. Chief information security officer (CISO ); c. Internal audit  may attend as an “observer .
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
