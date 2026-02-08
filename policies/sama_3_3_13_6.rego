package sama_3_3_13_6

import data.lib.utils

# Control ID: 3.3.13.6
# Description: use of multi -factor authentication mechanisms : a. multi -factor authentication  should be used during the registration process for the customer in order  to use of electronic banking services; b. multi -factor authentication should be implemented for all electronic banking services available to customers; c. the use of hard  and soft tokens should be password protected; d. revoking the access of customers after 3 successive incorrect passwords or invalid PINs; e. the process for changing the customer mobile number should only be done from either a branch or ATM; f. the processes for requesting and activating of the multi -factor authentication should be done through different delivery channels ; g. multi -factor authentication should be implemented for  the following processes: 1. sign-on; 2. adding or modifying beneficiaries; 3. adding utility and government payment services; 4. high -risk transactions (when it exceeds predefined limits); 5. password  reset;
# Requirement: Ensure compliance with 3.3.13.6 for AWS, GCP, Azure, OCI

default allow = false


# AWS Rule
allow {
    input.resource_type == "aws_iam_account_password_policy"
    input.require_uppercase_characters == true
    input.require_lowercase_characters == true
    input.require_numbers == true
    input.require_symbols == true
}

# Google Cloud Rule
allow {
    input.resource_type == "google_project_organization_policy"
}

# Azure Rule
allow {
    input.resource_type == "azurerm_role_assignment"
}

# OCI Rule
allow {
    input.resource_type == "oci_identity_authentication_policy"
}


deny[msg] {
    not allow
    msg := sprintf("Resource '%v' does not comply with SAMA Control 3.3.13.6", [input.resource_name])
}
