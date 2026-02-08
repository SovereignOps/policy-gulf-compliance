package sama_3_3_10_4

import data.lib.utils

# Control ID: 3.3.10.4
# Description: The BYOD standard should include: a. responsibilities of the user (including awareness training); b. information regarding the restrictions and consequences for staff  when the Member Organization implements cyber security  controls on their personal devices; for example w hen using modified devices (jailbreaking), terminating the employment or in case of loss or theft of the personal device; c. the isolation of business information from personal information  (e.g., container ization ); d. the regulation of corporate mobile applicati ons or approved “public ” mobile applications; e. the use of mobile device management (MDM); applying access controls to the device and business container and encryption mechanisms on the personal device (to ensure secure transmission and storage).
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
