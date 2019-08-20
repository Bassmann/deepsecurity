import json
import os
import sys
import warnings
import deepsecurity as api
from deepsecurity.rest import ApiException
from datetime import datetime
from pprint import pprint


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
api_instance = api.AdministratorsApi(api.ApiClient(configuration))
api_roles = api.AdministratorRolesApi(api.ApiClient(configuration))

# Add column titles to comma-separated values string
csv = "Username;Active;Last Sign in;Role\n"

try:

    # list all roles and store role names in dictionary with id as key
    roles = api_roles.list_administrator_roles(api_version)

    roles_dict = {}

    for role in roles.roles:
        roles_dict[role.id] = role.name

    # list all users on the system
    admins = api_instance.list_administrators(api_version)
    for admin in admins.administrators:
        module_info = []

        module_info.append(admin.username)
        module_info.append(admin.active)

        if admin.last_sign_in:
            posix_time = int(admin.last_sign_in)/1000
            last_sign_in = datetime.fromtimestamp(posix_time).isoformat()
        else:
            last_sign_in = None

        module_info.append(last_sign_in)
        module_info.append(roles_dict[admin.role_id])

        # Add the module info to the CSV string
        csv += format_for_csv(module_info)

    with open("../users.csv", "w") as text_file:
        text_file.write(csv)

except ApiException as e:
    print("An exception occurred when calling Administratiors..list_administrators: %s\n" % e)
