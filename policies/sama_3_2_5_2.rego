package sama_3_2_5_2

import data.lib.utils

# Control ID: 3.2.5.2
# Description: Cyber security  audits should be performe d according to the Member Organization’s audit manual and audit plan. 3.3 Cyber  Security Operations and Technology In order to safeguard the protection of the operations and technology of the Member Organization's information assets and its staff , third parties and customers, the Member Organizations have to ensure that security requirements for their information assets and the supporting processes are defined, approved and implemented. The compliance with these cyber security  requirements should be monitored and the effectiveness of the cyber security  controls should be periodically  measured and evaluated in order to identify potential revisions of the controls or measurements.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
