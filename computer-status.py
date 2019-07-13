from __future__ import print_function
import sys
import warnings
import deepsecurity
from deepsecurity.rest import ApiException
from pprint import pprint

# Setup
if not sys.warnoptions:
    warnings.simplefilter("ignore")
configuration = deepsecurity.Configuration()
configuration.host = 'https://app.deepsecurity.trendmicro.com/api'

# Authentication
configuration.api_key['api-secret-key'] = 'E93F360E-D8F0-AD7B-CA69-948C43CACB9E:3925613D-B360-AF16-A63F-952436C96350:RNE8zirCu3LWPhBMLUlBOG9jzgM0kHBrgxEeUiJIbaI='

# Initialization
# Set Any Required Values
api_instance = deepsecurity.ComputersApi(deepsecurity.ApiClient(configuration))
api_version = 'v1'
expand_options = deepsecurity.Expand(deepsecurity.Expand.all_virtual_machine_summaries)
# expand_options.add(deepsecurity.Expand.intrusion_prevention)
# expand_options.add(deepsecurity.Expand.anti_malware)
expand = expand_options.list()
overrides = False

# Create a search filter with maximum returned items
search_filter = deepsecurity.SearchFilter()
search_filter.max_items = 1000

try:
    computers = api_instance.search_computers(api_version, search_filter=search_filter, expand=expand, overrides=overrides)
    for computer in computers.computers:
        if computer.azure_vm_virtual_machine_summary:
            print('{} {}'.format(computer.host_name,computer.azure_vm_virtual_machine_summary.state))

except ApiException as e:
    print("An exception occurred when calling ComputersApi.list_computers: %s\n" % e)
