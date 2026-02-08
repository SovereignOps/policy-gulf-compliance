import csv
import os
import re

CSV_FILE = 'sama_controls_matrix.csv'
OUTPUT_DIR = 'policy-gulf-compliance/policies'

# Resource Mapping based on keywords
RESOURCE_MAPPING = {
    'encryption': {
        'aws': 'aws_s3_bucket',
        'google': 'google_storage_bucket',
        'azure': 'azurerm_storage_account',
        'oci': 'oci_objectstorage_bucket'
    },
    'cryptographic': {
        'aws': 'aws_s3_bucket',
        'google': 'google_storage_bucket',
        'azure': 'azurerm_storage_account',
        'oci': 'oci_objectstorage_bucket'
    },
    'network': {
        'aws': 'aws_security_group',
        'google': 'google_compute_firewall',
        'azure': 'azurerm_network_security_group',
        'oci': 'oci_core_security_list'
    },
    'firewall': {
        'aws': 'aws_security_group',
        'google': 'google_compute_firewall',
        'azure': 'azurerm_network_security_group',
        'oci': 'oci_core_security_list'
    },
    'log': {
        'aws': 'aws_cloudtrail',
        'google': 'google_logging_project_sink',
        'azure': 'azurerm_monitor_log_profile',
        'oci': 'oci_logging_log'
    },
    'monitor': {
        'aws': 'aws_cloudtrail',
        'google': 'google_logging_project_sink',
        'azure': 'azurerm_monitor_log_profile',
        'oci': 'oci_logging_log'
    },
    'audit': {
        'aws': 'aws_cloudtrail',
        'google': 'google_logging_project_sink',
        'azure': 'azurerm_monitor_log_profile',
        'oci': 'oci_logging_log'
    },
    'access': {
        'aws': 'aws_iam_user',
        'google': 'google_project_iam_member',
        'azure': 'azurerm_role_assignment',
        'oci': 'oci_identity_user'
    },
    'identity': {
        'aws': 'aws_iam_user',
        'google': 'google_project_iam_member',
        'azure': 'azurerm_role_assignment',
        'oci': 'oci_identity_user'
    },
    'backup': {
        'aws': 'aws_db_instance',
        'google': 'google_sql_database_instance',
        'azure': 'azurerm_sql_server',
        'oci': 'oci_database_db_system'
    },
    'recovery': {
        'aws': 'aws_db_instance',
        'google': 'google_sql_database_instance',
        'azure': 'azurerm_sql_server',
        'oci': 'oci_database_db_system'
    }
}

DEFAULT_RESOURCES = {
    'aws': 'aws_resource',
    'google': 'google_resource',
    'azure': 'azurerm_resource',
    'oci': 'oci_resource'
}

def clean_filename(text):
    # Remove non-alphanumeric characters and replace spaces with underscores
    text = re.sub(r'[^a-zA-Z0-9]', '_', text)
    return text.lower()

def get_resources_for_control(description):
    desc_lower = description.lower()
    for keyword, mapping in RESOURCE_MAPPING.items():
        if keyword in desc_lower:
            return mapping
    return DEFAULT_RESOURCES

def generate_rego_content(control_id, description, resources):
    package_name = f"sama_{clean_filename(control_id)}"
    
    rego_template = f"""package {package_name}

import data.lib.utils

# Control ID: {control_id}
# Description: {description}
# Requirement: Ensure compliance with {control_id} for {resources['aws']}, {resources['google']}, {resources['azure']}, {resources['oci']}

default allow = false

# AWS Rule
allow {{
    input.resource_type == "{resources['aws']}"
    # Add specific logic here based on implementation details
    # For now, we check if the resource exists and has tags (placeholder)
    count(input.resources) > 0
}}

# Google Cloud Rule
allow {{
    input.resource_type == "{resources['google']}"
    count(input.resources) > 0
}}

# Azure Rule
allow {{
    input.resource_type == "{resources['azure']}"
    count(input.resources) > 0
}}

# OCI Rule
allow {{
    input.resource_type == "{resources['oci']}"
    count(input.resources) > 0
}}

deny[msg] {{
    input.resource_type == "{resources['aws']}"
    not allow
    msg := sprintf("AWS resource '%v' does not comply with SAMA Control {control_id}", [input.resource_name])
}}

deny[msg] {{
    input.resource_type == "{resources['google']}"
    not allow
    msg := sprintf("Google resource '%v' does not comply with SAMA Control {control_id}", [input.resource_name])
}}

deny[msg] {{
    input.resource_type == "{resources['azure']}"
    not allow
    msg := sprintf("Azure resource '%v' does not comply with SAMA Control {control_id}", [input.resource_name])
}}

deny[msg] {{
    input.resource_type == "{resources['oci']}"
    not allow
    msg := sprintf("OCI resource '%v' does not comply with SAMA Control {control_id}", [input.resource_name])
}}
"""
    return rego_template

def main():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    with open(CSV_FILE, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        count = 0
        for row in reader:
            if row['Category'] == 'Tech':
                control_id = row['Control ID']
                description = row['Description']
                
                # Determine resources based on description keywords
                resources = get_resources_for_control(description)
                
                # Create filename
                filename = f"sama_{clean_filename(control_id)}.rego"
                filepath = os.path.join(OUTPUT_DIR, filename)
                
                # Generate content
                content = generate_rego_content(control_id, description, resources)
                
                with open(filepath, 'w', encoding='utf-8') as rego_file:
                    rego_file.write(content)
                
                print(f"Generated {filepath}")
                count += 1
        
        print(f"Total policies generated: {count}")

if __name__ == "__main__":
    main()
