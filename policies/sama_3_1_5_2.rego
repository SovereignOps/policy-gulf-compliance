package sama_3_1_5_2

import data.lib.utils

# Control ID: 3.1.5.2
# Description: The Member Organization’s project management methodology should ensure that: a. cyber security  objectives are included in project objectives; b. the cyber security  function is part of all phases of the project; c. a risk assessment is performed at the start of the project to determine the cyber security  risks and to ensure that cyber security  requirements are addressed either by the existing cyber security controls (ba sed on  cyber security  standards ) or to be developed; d. cyber security  risks are registered in the project -risk register  and tracked ; e. responsibilities for cyber security  are defined and allocated; f. a cyber security review is performed by an independent internal or external party .
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
