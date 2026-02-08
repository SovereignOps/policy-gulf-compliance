package sama_3_3_16_3

import data.lib.utils

# Control ID: 3.3.16.3
# Description: The threat intelligence management process should include: a. the use of internal sources, such as access control, application and infrastructure logs, IDS, IPS, security tooling, Security Information and Event Monitoring (SIEM), support functions  (e.g. , Legal, Audit, IT Helpdesk, Forensics, Fraud Management, Risk Management, Compliance); b. the use of reliable and relevant external sources, such as  SAMA, government agencies, security forums, (security) vendors, security organizations and specia list notification services; c. a defined methodology to analyze the threat information periodically ; d. the relevant details on identified or collected threats, such as  modus operandi, actors, motivation and type of threats; e. the relevance of the derived intellig ence and the action -ability for follow -up (for e.g. , SOC, Risk Management); f. sharing the relevant intelligence with the relevant stakeholders (e.g. , SAMA, BCIS  members).
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
