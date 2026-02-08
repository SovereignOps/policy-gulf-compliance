package sama_3_3_2_3

import data.lib.utils

# Control ID: 3.3.2.3
# Description: The physical security process should include  (but not limited to) : a. physical entry controls (including visitor security); b. monitoring and surveillance (e.g., CCTV, ATMs GPS tracking, sensitivity sensors); c. protection of data centers and data rooms; d. envir onmental protection; e. protection of information assets during lifecycle (including transport and secure disposal , avoiding unauthorized access and (un)intended data leakage .
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
