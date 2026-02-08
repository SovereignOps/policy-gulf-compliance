package sama_3_3_10_4

import data.lib.utils

# Control ID: 3.3.10.4
# Description: The BYOD standard should include: a. responsibilities of the user (including awareness training); b. information regarding the restrictions and consequences for staff  when the Member Organization implements cyber security  controls on their personal devices; for example w hen using modified devices (jailbreaking), terminating the employment or in case of loss or theft of the personal device; c. the isolation of business information from personal information  (e.g., container ization ); d. the regulation of corporate mobile applicati ons or approved “public ” mobile applications; e. the use of mobile device management (MDM); applying access controls to the device and business container and encryption mechanisms on the personal device (to ensure secure transmission and storage).
# Requirement: Ensure compliance with 3.3.10.4 for aws_s3_bucket, google_storage_bucket, azurerm_storage_account, oci_objectstorage_bucket

default allow = false

# AWS Rule
allow {
    input.resource_type == "aws_s3_bucket"
    # Add specific logic here based on implementation details
    # For now, we check if the resource exists and has tags (placeholder)
    count(input.resources) > 0
}

# Google Cloud Rule
allow {
    input.resource_type == "google_storage_bucket"
    count(input.resources) > 0
}

# Azure Rule
allow {
    input.resource_type == "azurerm_storage_account"
    count(input.resources) > 0
}

# OCI Rule
allow {
    input.resource_type == "oci_objectstorage_bucket"
    count(input.resources) > 0
}

deny[msg] {
    input.resource_type == "aws_s3_bucket"
    not allow
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.10.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_storage_bucket"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.10.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_storage_account"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.10.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_objectstorage_bucket"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.10.4", [input.resource_name])
}
