package sama_3_3_8_4

import data.lib.utils

# Control ID: 3.3.8.4
# Description: The infrastructure security standards should cover all instances of infrastructure available  in the main datacenter(s) , the disaster recovery data site(s)  and office spaces.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
