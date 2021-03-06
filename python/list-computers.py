import json
import os
import sys
import warnings
import deepsecurity as api
from deepsecurity.rest import ApiException
from datetime import datetime


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
property_file = os.path.dirname(os.path.abspath(__file__)) + '/../properties.json'

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
api_instance = api.ComputersApi(api.ApiClient(configuration))
# Add AV and IPS information
expand_options = api.Expand()
expand_options.add(api.Expand.computer_status)
expand_options.add(api.Expand.interfaces)
expand_options.add(api.Expand.azure_arm_virtual_machine_summary)
expand = expand_options.list()
overrides = False

# Set search criteria
search_criteria = api.SearchCriteria()
search_criteria.id_value = 0
search_criteria.id_test = "greater-than"

# Create a search filter with maximum returned items
page_size = 100
search_filter = api.SearchFilter()
search_filter.max_items = page_size
search_filter.search_criteria = [search_criteria]

# Add column titles to comma-separated values string
csv = "Host Name;Displayname;DNS Name;Agent version;Platform;IP Address;Agent Status;Agent Status Message;PolicyId;GroupId;Last Communication;Last Policy Sent;Last Policy Success;Update Status;AM Module State;AM Status;AM Status Message;AM Update Status;IPS Status;IPS Status Message\n"

try:
    # Perform the search and do work on the results
    print("Start reading computers")
    while True:
        computers = api_instance.search_computers(api_version, search_filter=search_filter, expand=expand, overrides=False)
        num_found = len(computers.computers)

        if num_found == 0:
            print("No computers found.")
            break

        for computer in computers.computers:
            # Module information to add to the CSV string
            module_info = []

            module_info.append(computer.host_name)
            module_info.append(computer.display_name)

            if computer.azure_arm_virtual_machine_summary:
                module_info.append(computer.azure_arm_virtual_machine_summary.dns_name)
            else:
                module_info.append("None")
            
            module_info.append(computer.agent_version)
            module_info.append(computer.platform)

            ips_list = [""]
            if computer.interfaces:
                for interface in computer.interfaces.interfaces:
                    if type(interface.ips) is list:
                        ips_list.append(", ".join(interface.ips))

            if computer.azure_arm_virtual_machine_summary:
                if computer.azure_arm_virtual_machine_summary.public_ip_address:
                    ips_list.append(computer.azure_arm_virtual_machine_summary.public_ip_address)
                if computer.azure_arm_virtual_machine_summary.private_ip_address:
                    ips_list.append(computer.azure_arm_virtual_machine_summary.private_ip_address)

            module_info.append(" ".join(ips_list))
            module_info.append(computer.computer_status.agent_status)
            agent_status_message = ' '.join(computer.computer_status.agent_status_messages)

            module_info.append(agent_status_message)

            module_info.append(computer.policy_id)
            module_info.append(computer.group_id)

            if computer.last_agent_communication:
                posix_time = int(computer.last_agent_communication)/1000
                last_comm = datetime.fromtimestamp(posix_time).isoformat()
            else:
                last_comm = None

            if computer.last_send_policy_request:
                posix_time = int(computer.last_send_policy_request)/1000
                last_send = datetime.fromtimestamp(posix_time).isoformat()
            else:
                last_send = None

            if computer.last_send_policy_success:
                posix_time = int(computer.last_send_policy_success)/1000
                last_success = datetime.fromtimestamp(posix_time).isoformat()
            else:
                last_success = None

            module_info.append(last_comm)
            module_info.append(last_send)
            module_info.append(last_success)

            # Add the module info to the CSV string
            csv += format_for_csv(module_info)

        # Get the ID of the last computer in the page and return it with the
        # number of computers on the page
        last_id = computers.computers[-1].id
        search_criteria.id_value = last_id
        print("Last ID: " + str(last_id), "Computers found: " + str(num_found))

        if num_found != page_size:
            break

    with open("../output/computers.csv", "w") as text_file:
        text_file.write(csv)

except ApiException as e:
    print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)
