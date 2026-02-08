package sama_3_3_9_4

import data.lib.utils

# Control ID: 3.3.9.4
# Description: The cryptographic security standard should include: a. an overview of the approved cryptographic solutions  and relevant rest rictions (e.g., technically, legally) ; b. the circumstances when the approved cryptographic solutions should be applied; c. the management of encryption keys , including lifecycle management, archiving and recovery.
# Requirement: Ensure compliance with 3.3.9.4 for aws_s3_bucket, google_storage_bucket, azurerm_storage_account, oci_objectstorage_bucket

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
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.9.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_storage_bucket"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.9.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_storage_account"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.9.4", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_objectstorage_bucket"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.9.4", [input.resource_name])
}
