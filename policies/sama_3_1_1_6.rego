package sama_3_1_1_6

import data.lib.utils

# Control ID: 3.1.1.6
# Description: The cyber security  function should be independent from the information technology function. To avoid any conflict of interest, the cyber security  function and informa tion technology function should have separate reporting lines, budgets and staff evaluations.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
