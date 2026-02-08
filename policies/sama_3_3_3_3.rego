package sama_3_3_3_3

import data.lib.utils

# Control ID: 3.3.3.3
# Description: The asset management process should include: a. a unified register; b. ownership and custodianship of information assets; c. the reference to relevant other processes , depending on asset management; d. information asset  classification, labeling and handling ; e. the discovery of ne w information assets .
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
