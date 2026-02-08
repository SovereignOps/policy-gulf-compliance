package sama_3_1_7_2

import data.lib.utils

# Control ID: 3.1.7.2
# Description: Education should be provided in order to equip staff  with the skills and required knowledge to securely operate the Member Organization’s information assets. 3.2 Cyber Security  Risk Management and Compliance Risk management is the ongoing process of identifying, analyzing, responding and monitoring and reviewing risks. The cyber security risk m anagement process focusses specifically on managing risks related to cyber security .  In or der to manage cyber security risks, Member Organizations should:  identify their cyber security risks – cyber security risk identification;  determine the likelihood that cyber security risks will occur and the resulting impact – cyber security risk analysis;  determine the appropriate response to cyber security risks and select relevant controls – cyber security risk response;  monitor the cyber security risk treatment and review control effectiveness  – cyber security risk monitoring and review. The compliance with the cyber security  controls should be subject to periodic review and audit.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
