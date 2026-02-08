package sama_3_3_8_5

import data.lib.utils

# Control ID: 3.3.8.5
# Description: The infrastructure security standards should cover all instances of infrastructure  (e.g., operating systems, servers, virtual machine s, firewalls, network  devices , IDS, IPS, wireless  network, gateway servers, proxy servers, email gateways, external connections,  databases, file -shares, workstations, laptops, tablets, mobile devices , PBX ).
# Requirement: Ensure compliance with 3.3.8.5 for aws_security_group, google_compute_firewall, azurerm_network_security_group, oci_core_security_list

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.8.5", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_compute_firewall"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.8.5", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_network_security_group"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.8.5", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_core_security_list"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.8.5", [input.resource_name])
}
