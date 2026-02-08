package sama_3_3_14_4

import data.lib.utils

# Control ID: 3.3.14.4
# Description: The security event management process should include  requirements for : a. the establishment of a designated team  resp onsible for security monitoring  (i.e., Security Operations Center (SOC) ); b. skilled and (continuously) trained staff; c. a restricted area to facilitate SOC activities and workspaces; d. resources required continuous security event monitoring activities (24x7); e. detection and handling of malicious code and software; f. detection and handling of security or suspicious events and anomalies; g. deployment of security network packet analysis solution ; h. adequately protected logs; i. periodic compliance monitoring of applications and infrastructure cyber security  standards j. automated and centralized analysis of security loggings and correlation of event or patterns (i.e. , Security Information and Event Management  (SIEM )); k. reporting of cyber security  incidents ; l. independent periodic testing of the effectiveness of the security operations center (e.g. , red- teaming).
# Requirement: Ensure compliance with 3.3.14.4 for AWS, GCP, Azure, OCI

default allow = false


# AWS Rule
allow {
    input.resource_type == "aws_cloudtrail"
    input.enable_logging == true
}
allow {
    input.resource_type == "aws_flow_log"
}

# Google Cloud Rule
allow {
    input.resource_type == "google_logging_project_sink"
}

# Azure Rule
allow {
    input.resource_type == "azurerm_monitor_log_profile"
}

# OCI Rule
allow {
    input.resource_type == "oci_logging_log"
    input.is_enabled == true
}


deny[msg] {
    not allow
    msg := sprintf("Resource '%v' does not comply with SAMA Control 3.3.14.4", [input.resource_name])
}
