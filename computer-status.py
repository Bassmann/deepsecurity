import json
import os
import sys
import warnings
import deepsecurity as api
from deepsecurity.rest import ApiException

# Setup
if not sys.warnoptions:
    warnings.simplefilter("ignore")

# Get the DSM URL and API key from a JSON file
property_file = os.path.dirname(os.path.abspath(__file__)) + '/properties.json'
print(property_file)

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
expand_options = api.Expand(api.Expand.all_virtual_machine_summaries)
# expand_options.add(api.Expand.intrusion_prevention)
# expand_options.add(api.Expand.anti_malware)
expand = expand_options.list()
overrides = False

# Create a search filter with maximum returned items
search_filter = api.SearchFilter()
search_filter.max_items = 10

try:
    computers = api_instance.search_computers(api_version, search_filter=search_filter, expand=expand, overrides=overrides)
    for computer in computers.computers:
        if computer.azure_vm_virtual_machine_summary:
            print('{} {} ({})'.format(computer.host_name, computer.last_ip_used, computer.azure_vm_virtual_machine_summary.state))
        else:
            print('{} {}'.format(computer.host_name,computer.last_ip_used))

except ApiException as e:
    print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)
