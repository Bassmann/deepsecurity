import json
import os
import sys
import warnings
import deepsecurity as api
from deepsecurity.rest import ApiException


def format_for_csv(line_item):
    """Converts a list into a string of comma-separated values, ending with a newline character.
    :param line_item: The list of lists to convert to a string of comma-spearated values
    :return: A string that can be saved as a CSV file.
    """

    csv_line = ""
    for num, item in enumerate(line_item):
        csv_line += str(item)
        if num != (len(line_item) - 1):
            csv_line += ";"
        else:
            csv_line += "\n"

    return csv_line


# Setup
if not sys.warnoptions:
    warnings.simplefilter("ignore")

# Get the DSM URL and API key from a JSON file
property_file = os.path.dirname(os.path.abspath(__file__)) + '/properties.json'

with open(property_file) as raw_properties:
    properties = json.load(raw_properties)

secret_key = properties['secretkey']
url = properties['url']
api_version = 'v1'

# Add DSM host information to the API client configuration
configuration = api.Configuration()
configuration.host = url
configuration.api_key['api-secret-key'] = secret_key

# Initialization
# Set Any Required Values
api_instance = api.PoliciesApi(api.ApiClient(configuration))

# Add column titles to comma-separated values string
csv = "Policy ID;Name;Parent ID;Antimalware;Application control;firewall;integrity monitoring;interface types;intrusion prevention;log_inspection;communication direction;heartbeat interval\n"

overrides = False

try:
    policies = api_instance.list_policies(api_version, overrides=overrides)
    defaults = api_instance.list_default_settings(api_version)

    for policy in policies.policies:
        module_info = []
        module_info.append(policy.id)
        module_info.append(policy.name)
        module_info.append(policy.parent_id)
        module_info.append(policy.anti_malware.module_status.status_message)
        module_info.append(policy.application_control.module_status.status_message)
        module_info.append(policy.firewall.module_status.status_message)
        module_info.append(policy.integrity_monitoring.module_status.status_message)
        if policy.interface_types:
            module_info.append(policy.interface_types.module_status.status_message)
        else:
            module_info.append("None")
        module_info.append(policy.intrusion_prevention.module_status.status_message)
        module_info.append(policy.log_inspection.module_status.status_message)

        module_info.append(policy.policy_settings.platform_setting_agent_communications_direction.value)
        module_info.append(policy.policy_settings.platform_setting_heartbeat_interval.value)
        # Add the module info to the CSV string
        csv += format_for_csv(module_info)

    with open("output/policies.csv", "w") as text_file:
        text_file.write(csv)


except ApiException as e:
    print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)
