package sama_3_2_5_1

import data.lib.utils

# Control ID: 3.2.5.1
# Description: Cyber security  audits should be performed independently and according to generally accepted auditing standards  and SAMA cyber security framework .
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
