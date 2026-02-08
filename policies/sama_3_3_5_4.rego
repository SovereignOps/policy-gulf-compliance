package sama_3_3_5_4

import data.lib.utils

# Control ID: 3.3.5.4
# Description: user access requests are formally approved in accordance with business and compliance requirements (i.e. , need -to-have and need -to-know  to avoid unauthorized access  and (un)intended data leakage ));
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
