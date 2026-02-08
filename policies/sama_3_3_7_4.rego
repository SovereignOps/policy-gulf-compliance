package sama_3_3_7_4

import data.lib.utils

# Control ID: 3.3.7.4
# Description: The change management process should include: a. cyber security  requirements for controlling changes to information assets, such as  assessing the impact of requested changes, classification  of changes and the review of changes; b. security testing, which should (if applicable) include: 1. penetration testing; 2. code review if applications are developed internally; 3. code review of externally developed applications and if the source code is available
# Requirement: Ensure compliance with 3.3.7.4 for aws_resource, google_resource, azurerm_resource, oci_resource

default allow = false

# AWS Rule
allow {
    input.resource_type == "aws_resource"
    # Add specific logic here based on implementation details
    # For now, we check if the resource exists and has tags (placeholder)
    count(input.resources) > 0
}

# Google Cloud Rule
allow {
    input.resource_type == "google_resource"
    count(input.resources) > 0
}

# Azure Rule
allow {
    input.resource_type == "azurerm_resource"
    count(input.resources) > 0
}

# OCI Rule
allow {
    input.resource_type == "oci_resource"
    count(input.resources) > 0
}

deny[msg] {
    input.resource_type == "aws_resource"
    not allow
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.7.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_resource"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.7.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_resource"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.7.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_resource"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.7.4", [input.resource_name])
}
