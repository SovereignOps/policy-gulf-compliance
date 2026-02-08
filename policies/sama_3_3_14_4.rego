package sama_3_3_14_4

import data.lib.utils

# Control ID: 3.3.14.4
# Description: The security event management process should include  requirements for : a. the establishment of a designated team  resp onsible for security monitoring  (i.e., Security Operations Center (SOC) ); b. skilled and (continuously) trained staff; c. a restricted area to facilitate SOC activities and workspaces; d. resources required continuous security event monitoring activities (24x7); e. detection and handling of malicious code and software; f. detection and handling of security or suspicious events and anomalies; g. deployment of security network packet analysis solution ; h. adequately protected logs; i. periodic compliance monitoring of applications and infrastructure cyber security  standards j. automated and centralized analysis of security loggings and correlation of event or patterns (i.e. , Security Information and Event Management  (SIEM )); k. reporting of cyber security  incidents ; l. independent periodic testing of the effectiveness of the security operations center (e.g. , red- teaming).
# Requirement: Ensure compliance with 3.3.14.4 for aws_security_group, google_compute_firewall, azurerm_network_security_group, oci_core_security_list

default allow = false

# AWS Rule
allow {
    input.resource_type == "aws_security_group"
    # Add specific logic here based on implementation details
    # For now, we check if the resource exists and has tags (placeholder)
    count(input.resources) > 0
}

# Google Cloud Rule
allow {
    input.resource_type == "google_compute_firewall"
    count(input.resources) > 0
}

# Azure Rule
allow {
    input.resource_type == "azurerm_network_security_group"
    count(input.resources) > 0
}

# OCI Rule
allow {
    input.resource_type == "oci_core_security_list"
    count(input.resources) > 0
}

deny[msg] {
    input.resource_type == "aws_security_group"
    not allow
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.14.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_compute_firewall"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.14.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_network_security_group"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.14.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_core_security_list"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.14.4", [input.resource_name])
}
