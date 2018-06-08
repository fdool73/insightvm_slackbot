
import logging
from logging import handlers
import os
import sys


class Logger():

    # non-default arguments cannot follow default arguments.
    def __init__(self, log_level, log_file_name=None):

        # Set root directory for logs.
        self.log_file_base_dir = log_file_name

        # Creates base directory if it does not exist.
        if not os.path.exists(self.log_file_base_dir):
            print("Directory did not exist; Creating: {}".format(self.log_file_base_dir))
            os.makedirs(self.log_file_base_dir)

        self.log_file_name = 'slackbot.log'

        # Construct full log path.
        self.full_log_file_name = os.path.join(self.log_file_base_dir, self.log_file_name)

        if log_level not in range(0, 6):
            print("[-] Invalid loglevel '{}'.  Must be 1-5 inclusive.".format(log_level))
            sys.exit(0)

        logging.basicConfig(
            level=log_level * 10,
            format="%(asctime)s [%(threadName)-12.12s] [%(levelname)s] %(message)s",
            handlers=[logging.FileHandler(self.full_log_file_name),
                      logging.StreamHandler(),
                      handlers.RotatingFileHandler(
                          self.full_log_file_name,
                          maxBytes=1024 * 1024,  # 1MB
                          backupCount=5)]
        )

        self.root_logger = logging.getLogger(__name__)
