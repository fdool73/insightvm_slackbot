
import logging
from logging import handlers
import os
import sys


class Logger():

    # non-default arguments cannot follow default arguments.
    def __init__(self, log_level, log_file_name=None):

        # Set root directory for logs.
        self.log_file_base_dir = log_file_name

        write_log = os.path.exists(self.log_file_base_dir)

        # Creates base directory if it does not exist.
        if not write_log:
            print("Directory did not exist; Creating: {}".format(self.log_file_base_dir))

            # Check is log dir is writable, if not, just log to STDOUT
            try:
                os.makedirs(self.log_file_base_dir)
                write_log = True
            except PermissionError:
                print("Insufficient permissions for {}. Logging to STDOUT only".format(self.log_file_base_dir))
                write_log = False

        if log_level not in range(0, 6):
            print("[-] Invalid loglevel '{}'.  Must be 1-5 inclusive.".format(log_level))
            sys.exit(0)

        # Minimize Python requests (and the underlying urllib3 library) logging level.
        logging.getLogger("requests").setLevel(logging.WARN)
        logging.getLogger("urllib3").setLevel(logging.WARN)

        if write_log:
            self.log_file_name = 'slackbot.log'

            # Construct full log path.
            self.full_log_file_name = os.path.join(self.log_file_base_dir, self.log_file_name)

            logging.basicConfig(
                level=log_level * 10,
                format="%(asctime)s [%(threadName)-12.12s] [%(levelname)s] %(message)s",
                handlers=[logging.StreamHandler(),
                          handlers.RotatingFileHandler(
                              self.full_log_file_name,
                              maxBytes=1024 * 1024,  # 1MB
                              backupCount=5)]
            )

        else:
            logging.basicConfig(
                level=log_level * 10,
                format="%(asctime)s [%(threadName)-12.12s] [%(levelname)s] %(message)s",
                handlers=[logging.StreamHandler()]
            )

        self.root_logger = logging.getLogger(__name__)
