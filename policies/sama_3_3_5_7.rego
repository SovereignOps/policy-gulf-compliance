package sama_3_3_5_7

import data.lib.utils

# Control ID: 3.3.5.7
# Description: an audit trail of submitted, approved and processed user access requests and revocation requ ests should be established; c. user access management should be supported by automation; d. centralization of the identity and access management function; e. multi -factor authentication for sensitive and critical systems and profiles; f. privilege d and remote access management , which should address: 1. the allocation and restricted use of privileged and remote access , specifying : a. multi-factor authentication shoul d be used for all remote access; b. multi-factor authentication should be used for privilege access on critical s ystems based on a risk assessment ; 2. the periodic review of users with privileged and remote accounts ; 3. individual accountability ; 4. the use of non -personal privileged accounts , including: a. limitation and monitoring; b. confidentiality of passwords; c. changing passwords frequently and at the end of each session .
# Requirement: Ensure compliance with 3.3.5.7 for AWS, GCP, Azure, OCI

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
    msg := sprintf("Resource '%v' does not comply with SAMA Control 3.3.5.7", [input.resource_name])
}
