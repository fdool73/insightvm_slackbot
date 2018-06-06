#!/usr/bin/python3

# Statndard Libraries
import os
import queue
import sys
import threading
import time

# Third Party Libraries
from slackclient import SlackClient

# Custom Libraries
import helpers

# Strict code checking (in-case cli option -W error wasn't used)
import warnings
warnings.simplefilter('error')

# Minimum version check
MIN_VERSION_PY = (3, 6)
if sys.version_info < MIN_VERSION_PY:
    sys.exit("Python %s.%s or later is required." % MIN_VERSION_PY)

# Always a good security practice as a default
os.umask(0o027)


if __name__ == "__main__":
    # Parse secrets file
    SECRETS = helpers.SECRETS
    print('Parsed SECRETS file.')

    # Set up logger
    log_level = SECRETS['options']['log_level']
    log_location = SECRETS['options']['log_location']
    # Use as global var
    log = helpers.Logger(log_level, log_location).root_logger
    log.info('InsightVM Slack bot started.')
    log.info('Logging to {}'.format(log_location))

    # Get additoinal SECRETS parameters
    try:
        slack_token = SECRETS['slack']['token']
        insightvm_user = SECRETS['insightvm']['username']
        insightvm_pass = SECRETS['insightvm']['password']
    except KeyError:
        log.critical('Secrets file missing required parameters')
        sys.exit()

    # Instantiate Slack client
    slack_client = SlackClient(slack_token)
    log.info('Connecting to Slack.')

    # insightvm_bot's user ID in Slack: value is assigned after the bot starts up
    insightvm_bot_id = None

    # Initialize queue -- global
    scan_tasker_queue = queue.Queue()

    # Constants
    RTM_READ_DELAY = 1  # 1 second delay between reading from RTM
    THREADS = SECRETS['options']['workers']

    # Connect to Slack
    if slack_client.rtm_connect(with_team_state=False):
        log.info("InsightVM Bot connected and running!")

        # Start workers
        threads = []
        for i in range(THREADS):
            t = threading.Thread(target=helpers.worker, args=(
                scan_tasker_queue, slack_client, log))
            t.daemon = True
            t.start()
            threads.append(t)

        # Read bot's user ID by calling Web API method `auth.test`
        insightvm_bot_id = slack_client.api_call("auth.test")["user_id"]
        if not insightvm_bot_id:
            log.error('Failed Slack auth test -- exiting')
            sys.exit()

        log.debug('Passed Slack auth test')
        # Listen to Slack, receive and parse messages
        while True and insightvm_bot_id:
            try:
                command, channel, user = helpers.parse_bot_commands(slack_client.rtm_read(), insightvm_bot_id)
                username = slack_client.server.users.info(user)
                if command:
                    log.debug("Got message from Slack:")
                    log.debug('Command -- {}, Channel -- {}, User -- {}'.format(
                        command, channel, username))
                    response = helpers.handle_command(command, channel, user,
                                                      scan_tasker_queue)

                    # Sends the response back to the channel
                    log.debug(response)
                    slack_client.api_call("chat.postMessage", channel=channel,
                                          text=response)
                time.sleep(RTM_READ_DELAY)
            except KeyboardInterrupt:
                log.warning('Ctl^C -- SHUTTING DOWN!')
                sys.exit()
    else:
        log.critical("Connection failed. Exception traceback printed above.")
