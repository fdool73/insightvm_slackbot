"""
Helper to organize passwords, keys, and endpoints.
"""
# Standard Python libraries.
import json
import os
import sys

# Third party Python libraries.


# Custom Python libraries.


secrets_file_location = './keys/secrets.json'
SECRETS = {}
try:
    with open(secrets_file_location) as config_file:
        SECRETS = json.loads(config_file.read())
except OSError:
    mylogger.root_logger.critical("Error: {} does not exist.".format(secrets_file_location))
    sys.exit(1)
