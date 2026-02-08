package sama_3_3_15_4

import data.lib.utils

# Control ID: 3.3.15.4
# Description: The security incident management process should include  requirements for : a. the establishment of a designated team  responsible for security incident management ; b. skilled and (continuously) trained staff ; c. sufficient capacity available of certified forensic staff for handling major incidents (e.g., internal staff  or contracting a n external  forensic team ); d. a restricted area to facilitate the computer emergency response  team ( CERT ) workspaces; e. the classification of cyber security  incidents; f. the timely handling of cyber security  incidents , recording and monitoring progress; g. the protection of relevant evidence and loggings; h. post -incident activities, such as  forensics, root -cause analysis of the inc idents; i. reporting of suggested improvements to the CISO and the Committee; j. establish a cyber security incident repository.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
