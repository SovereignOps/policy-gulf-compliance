package sama_3_2_1_6

import data.lib.utils

# Control ID: 3.2.1.6
# Description: The cyber security risk management process should be initiated: a. at an early stage of the project; b. prior to critical change; c. when outsourcing  is being considered; d. when launching new products and technologies.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
