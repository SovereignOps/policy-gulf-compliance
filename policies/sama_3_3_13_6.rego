package sama_3_3_13_6

import data.lib.utils

# Control ID: 3.3.13.6
# Description: use of multi -factor authentication mechanisms : a. multi -factor authentication  should be used during the registration process for the customer in order  to use of electronic banking services; b. multi -factor authentication should be implemented for all electronic banking services available to customers; c. the use of hard  and soft tokens should be password protected; d. revoking the access of customers after 3 successive incorrect passwords or invalid PINs; e. the process for changing the customer mobile number should only be done from either a branch or ATM; f. the processes for requesting and activating of the multi -factor authentication should be done through different delivery channels ; g. multi -factor authentication should be implemented for  the following processes: 1. sign-on; 2. adding or modifying beneficiaries; 3. adding utility and government payment services; 4. high -risk transactions (when it exceeds predefined limits); 5. password  reset;
# Requirement: Ensure compliance with 3.3.13.6 for aws_iam_user, google_project_iam_member, azurerm_role_assignment, oci_identity_user

default allow = false

# AWS Rule
allow {
    input.resource_type == "aws_iam_user"
    # Add specific logic here based on implementation details
    # For now, we check if the resource exists and has tags (placeholder)
    count(input.resources) > 0
}

# Google Cloud Rule
allow {
    input.resource_type == "google_project_iam_member"
    count(input.resources) > 0
}

# Azure Rule
allow {
    input.resource_type == "azurerm_role_assignment"
    count(input.resources) > 0
}

# OCI Rule
allow {
    input.resource_type == "oci_identity_user"
    count(input.resources) > 0
}

deny[msg] {
    input.resource_type == "aws_iam_user"
    not allow
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control 3.3.13.6", [input.resource_name])
}

deny[msg] {
    input.resource_type == "google_project_iam_member"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control 3.3.13.6", [input.resource_name])
}

deny[msg] {
    input.resource_type == "azurerm_role_assignment"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control 3.3.13.6", [input.resource_name])
}

deny[msg] {
    input.resource_type == "oci_identity_user"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control 3.3.13.6", [input.resource_name])
}
