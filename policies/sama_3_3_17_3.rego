package sama_3_3_17_3

import data.lib.utils

# Control ID: 3.3.17.3
# Description: The vulnerability management process should include: a. all information assets; b. frequency of performing the vulner ability scan (risk -based); c. classification of vulnerabilities; d. defined timelines to mitigate  (per classification) ; e. prioritization for classified information assets; f. patch mana gement and method of deployment. 3.4 Third Party Cyber  Security When Member Organiza tions do rely on, or have to deal with third party services, it is key to ensure the same level of cyber security protection is implemented at the third party, as within the Member Organization. This paragraph describes how the cyber security  requirement s between the Member Organization and Third Parties should be organized, implemented and monitored. Third Parties in this Framework are defined as, information services providers, outsourcing providers, cloud computing providers, vendors, suppliers, govern mental agencies, etc.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
