package sama_3_3_15_7

import data.lib.utils

# Control ID: 3.3.15.7
# Description: The Member Organization should submit a formal incident report  ‘SAMA IT Risk Supervision’  after resuming operations , including  the following incident details : a. title of incident; b. classification of the incident (medium or high); c. date and time of incident  occurred ; d. date and time of incident detected; e. information assets involved; f. (technical) detai ls of the incident; g. root -cause analysis; h. corrective activities performed and planned; i. description of impact  (e.g., loss of data, disruption of services, unauthorized modification of data , (un)intended data leakage, number of customers impacted ); j. total est imated cost of incident; k. estimated cost of corrective actions.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
