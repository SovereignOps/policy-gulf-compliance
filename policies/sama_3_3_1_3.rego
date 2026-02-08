package sama_3_3_1_3

import data.lib.utils

# Control ID: 3.3.1.3
# Description: The human resource process shoul d include: a. cyber security  responsibilities and non -disclosure clauses within staff agreements (during and after the employment); b. staff  should receive cyber security  awareness at the start and during their employment; c. when disciplinary actions will be appli cable; d. screening and background check; e. post-employment cyber security  activities, such as : 1. revoking access rights; 2. returning information assets assigned (e.g. , access badge, tokens, mobile devices, all electronic and physical information).
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
