
import logging
import os
import sys


class Logger():

    # non-default arguments cannot follow default arguments.
    def __init__(self, log_level, log_file_name=None):

        # Set root directory for logs.
        self.log_file_base_dir = log_file_name
        self.master_log = "{}/master.log".format(self.log_file_base_dir)

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

        self.root_logger = logging.getLogger(self.full_log_file_name)
        self.log_formatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)s] %(message)s")  # ISO8601 datetime format by default.

        # Set up individual file logging.
        log_file_handler = logging.FileHandler(self.full_log_file_name)
        log_file_handler.setFormatter(self.log_formatter)
        self.root_logger.addHandler(log_file_handler)

        # Set up master file logging.
        master_log_file_handler = logging.FileHandler(self.master_log)
        master_log_file_handler.setFormatter(self.log_formatter)
        self.root_logger.addHandler(master_log_file_handler)

        # Setup console logging.
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(self.log_formatter)
        self.root_logger.addHandler(console_handler)

        # Assign log level.
        self.root_logger.setLevel(log_level * 10)
