package sama_3_3_13_11

import data.lib.utils

# Control ID: 3.3.13.11
# Description: obtaining approval of SAMA before launching a new  electronic banking service. c. ATMs and POS s: 1. prevention and detection of exploiting the ATM/POS application and infrastructure vulnerabilities (e.g. , cables, (USB) -ports, rebooting); 2. cyber security  measures , such as  hardening of operating systems, malware protection, privacy screens, masking of passwords or account numbers ( e.g., screen and receipt), geo-blocking (e.g., disable cards per default for outside GCC countries , disable magnetic strip transactions ), video monitoring (CCTV), revoking cards after 3 successive invalid PINs, anti-skimming solutions  (hardware/software) , and PIN-pad protection ; 3. remote stopping of ATMs in case of malicious activities. d. SMS instant notification services: 1. SMS messages should not contain sensitive data (e.g. , account balance  - except for credit cards) ; 2. SMS alert should be sent to both mobile numbers (old and new) when the customer’s mobile number has been changed; 3. SMS notification should be sent to the customer’s mobile number when requesting a new multi -factor authentication mechanism . 4. SMS notification should be sent  to the customer’s mobile number for all  retail and personal financial transactions. 5. SMS notification should be sent to the customer’s mobile number when beneficiaries are added, modified and activated.
# Requirement: Ensure compliance with 3.3.13.11 for aws_cloudtrail, google_logging_project_sink, azurerm_monitor_log_profile, oci_logging_log

default allow = false

# AWS Rule
allow {
    input.resource_type == "aws_cloudtrail"
    # Add specific logic here based on implementation details
    # For now, we check if the resource exists and has tags (placeholder)
    count(input.resources) > 0
}

# Google Cloud Rule
allow {
    input.resource_type == "google_logging_project_sink"
    count(input.resources) > 0
}

# Azure Rule
allow {
    input.resource_type == "azurerm_monitor_log_profile"
    count(input.resources) > 0
}

# OCI Rule
allow {
    input.resource_type == "oci_logging_log"
    count(input.resources) > 0
}

deny[msg] {
    input.resource_type == "aws_cloudtrail"
    not allow
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.13.11", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_logging_project_sink"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.13.11", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_monitor_log_profile"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.13.11", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_logging_log"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.13.11", [input.resource_name])
}
