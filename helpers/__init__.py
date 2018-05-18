import inspect
import os
import sys

if (sys.version_info[0] < 3) or ((sys.version_info[0] == 3) and (sys.version_info[1] < 6)):
    print("Python 3.6 or a more recent version is required.")
    sys.exit(0)

# Use this if you want to include modules from a subfolder.
subfolder = os.path.realpath(os.path.abspath(os.path.join(os.path.split(inspect.getfile(inspect.currentframe()))[0], ".")))
if subfolder not in sys.path:
    sys.path.insert(0, subfolder)


# Order matters.
from logger import Logger  # noqa
from secrets import SECRETS # noqa
from asyncdog import DataFetcher  # noqa
# Places functions in helpers. namespace instead of helpers.insightvm. namespace
from insightvm import *  # noqa.
# Places functions in helpers. namespace instead of helpers.utility. namespace
from utility import *  # noqa.
from slack import * # noqa
