package sama_3_3_13_11

import data.lib.utils

# Control ID: 3.3.13.11
# Description: obtaining approval of SAMA before launching a new  electronic banking service. c. ATMs and POS s: 1. prevention and detection of exploiting the ATM/POS application and infrastructure vulnerabilities (e.g. , cables, (USB) -ports, rebooting); 2. cyber security  measures , such as  hardening of operating systems, malware protection, privacy screens, masking of passwords or account numbers ( e.g., screen and receipt), geo-blocking (e.g., disable cards per default for outside GCC countries , disable magnetic strip transactions ), video monitoring (CCTV), revoking cards after 3 successive invalid PINs, anti-skimming solutions  (hardware/software) , and PIN-pad protection ; 3. remote stopping of ATMs in case of malicious activities. d. SMS instant notification services: 1. SMS messages should not contain sensitive data (e.g. , account balance  - except for credit cards) ; 2. SMS alert should be sent to both mobile numbers (old and new) when the customer’s mobile number has been changed; 3. SMS notification should be sent to the customer’s mobile number when requesting a new multi -factor authentication mechanism . 4. SMS notification should be sent  to the customer’s mobile number for all  retail and personal financial transactions. 5. SMS notification should be sent to the customer’s mobile number when beneficiaries are added, modified and activated.
# Requirement: Manual Verification

# This control requires manual verification of organizational processes/documentation.
# It cannot be automated via Terraform infrastructure checks.

default allow = false

allow {
    # Manual verification required
    true
}
