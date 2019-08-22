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
api_instance = api.AntiMalwareConfigurationsApi(api.ApiClient(configuration))
api_directories = api.DirectoryListsApi(api.ApiClient(configuration))

# Add column titles to comma-separated values string
am_csv = "Configuration ID;Name;alert_enabled;excluded_directory_list_id;excluded_file_extension_list_id;excluded_file_list_id;excluded_process_image_file_list_id;files_to_scan;network_directories_enabled;real_time_scan;scan_action_for_virus;scan_action_for_possible_malware;scan_action_for_other_threats;scan_action_for_spyware;scan_action_for_trojans\n"

dl_csv = "id;name;description;items\n"

try:
    api_response = api_instance.list_anti_malwares(api_version)
    directory_response = api_directories.list_directory_lists(api_version)

    dl_dict = {}

    for dlist in directory_response.directory_lists:
        dl_dict[dlist.id] = dlist.name
        module_info = []

        module_info.append(dlist.id)
        module_info.append(dlist.name)
        module_info.append(dlist.description)
        module_info.append(" ".join(dlist.items))

        # Add the module info to the CSV string
        dl_csv += format_for_csv(module_info)

    for amconfig in api_response.anti_malware_configurations:
        module_info = []
        module_info.append(amconfig.id)
        module_info.append(amconfig.name)
        module_info.append(amconfig.alert_enabled)
        if amconfig.excluded_directory_list_id:
            module_info.append(dl_dict[amconfig.excluded_directory_list_id])
        else:
            module_info.append("None")
        module_info.append(amconfig.excluded_file_extension_list_id)
        module_info.append(amconfig.excluded_file_list_id)
        module_info.append(amconfig.excluded_process_image_file_list_id)
        module_info.append(amconfig.files_to_scan)
        module_info.append(amconfig.network_directories_enabled)
        module_info.append(amconfig.real_time_scan)
        module_info.append(amconfig.scan_action_for_virus)
        module_info.append(amconfig.scan_action_for_possible_malware)
        module_info.append(amconfig.scan_action_for_other_threats)
        module_info.append(amconfig.scan_action_for_spyware)
        module_info.append(amconfig.scan_action_for_trojans)

        # Add the module info to the CSV string
        am_csv += format_for_csv(module_info)

    with open("output/AMSettings.csv", "w") as text_file:
        text_file.write(am_csv)

    with open("output/DirectoryLists.csv", "w") as text_file:
        text_file.write(dl_csv)

except ApiException as e:
    print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)
