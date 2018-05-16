#!/usr/bin/python3

# Statndard Libraries
import os
import queue
import sys
import threading
import time

# Third Party Libraries
from joblib import Parallel, delayed
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


def worker():
    """
    Worker function to take items off the queue and process them. This worker
    gets scan tasks, starts the scan, monitors scan progress, and returns scan
    results.
    """
    while True:
        # Get item off the queue, exit if nothing queued.
        item = scan_tasker_queue.get()
        log.debug('Worker started and got item from queue.')
        log.debug("Got {} targets from command.".format(len(item['target_list'])))
        if item is None:
            break

        # Determine site for IDs.
        # List placeholder, parrallel function returns a list of outputs
        site_asset_set = []
        log.info("Getting list of all sites.")
        sites = helpers.retrieve_all_site_ids()
        log.info('Retrieving target lists, this may take a while...')

        # Run site_membership in parrallel, this is the biggest bottleneck
        site_asset_list = Parallel(n_jobs=10, backend="threading")(
            delayed(helpers.site_membership)(site, item['target_list'])
            for site in sites.keys())

        # Dedup
        site_asset_set = set(site_asset_list)
        site_asset_set.remove(None)

        log.debug('List returned from parrallel processing: {}'.format(site_asset_set))

        # Parse site and address to determine any assets that do not live
        # in InsightVM.
        target_set = set()
        site_set = set()
        no_scan_set = set()
        # Get actual targets and site
        for site_asset_pair in site_asset_set:
            if site_asset_pair[0] == 0:
                no_scan_set.add(site_asset_pair[1])
            target_set.add(site_asset_pair[1])
            site_set.add(site_asset_pair[0])

        log.info('Site set: {}'.format(site_set))
        log.info('Target set: {}'.format(target_set))

        # Check if assets reside in more than one site, prompt for additional
        # info if needed.  All assets should/must reside in one common site.
        # Counting insightvm to handle different site errors.
        if len(site_set) > 1 and 'site id:' in item['command'].lower():
            try:
                scan_id = helpers.adhoc_site_scan(target_set, int(command.split(':'[1])))
                message = "<@{}> Scan ID: {} started".format(item['user'], scan_id)
            except SystemError as e:
                message = "<@{}> Scan ID: {} produced an error".format(item['user'])
                message += e
        elif len(site_set) > 1:
            message = '<@{}> Assets exist in multiple sites ({}). '
            message += 'Please re-run command with '
            message += '`@insightvm_bot scan <IPs> site id:<ID>``'
            message = message.format(item['user'], site_set)
        elif len(site_set) == 0:
            message = '<@{}> scan for {} *failed*.'
            message += '  Device(s) do not exist in insightvm :confounded:'
            message += ' Device must have been scanned previously through a normal scan.'
            message = message.format(item['user'], item['target_list'])
        else:
            try:
                scan_id = helpers.adhoc_site_scan(target_set, site_set.pop())
                message = "<@{}> Scan ID: {} started".format(item['user'], scan_id)
            except SystemError as e:
                message = "<@{}> Scan produced an error".format(item['user'])
                message += e

        if no_scan_set:
            message += 'These hosts do not exist in InsightVM, unable to scan: {}'.format(no_scan_set)

        # Respond to Slack with result
        log.info(message)
        slack_client.api_call(
            "chat.postMessage",
            channel=item['channel'],
            text=message
        )

        # Monitor scan for completion, simply break if scan has failed or other error
        while True and scan_id:
            time.sleep(60)
            scan = helpers.retrieve_scan_status(scan_id)
            log.info("Current statuts for Scan {}: {}".format(scan_id, scan['status']))
            if scan['status'] in ['running', 'integrating', 'dispatched']:
                continue
            else:
                break

        # Gather scan details
        if scan['status'] == 'finished':
            message = "<@{}> Scan ID: {} finished for {} at {}\n"
            message += "*Scan Duration*: {} minutes\n {}\n"
            message += "Report is being generated at https://insightvm.secops.rackspace.com/report/reports.jsp"
            message = message.format(item['user'], scan_id, item['target_list'],
                                     time.asctime(),
                                     time.strptime(scan['duration'], 'PT%MM%S.%fS').tm_min,
                                     scan['vulnerabilities'])
            if scan['vulnerabilities']['total'] == 0:
                message += helpers.get_gif()
        else:
            message = "<@{}> Scan ID: {} *failed* for"
            message += " {} at {} :sob:"
            message += "Please contact the TVA team."
            message = message.format(item['user'], scan_id, item['target_list'], time.asctime())

        # Respond in Slack with scan finished message.
        log.info(message)
        slack_client.api_call(
            "chat.postMessage",
            channel=item['channel'],
            text=message
        )

        log.debug('Worker done.')
        scan_tasker_queue.task_done()


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
        log.info("insightvm Bot connected and running!")

        # Start workers
        threads = []
        for i in range(THREADS):
            t = threading.Thread(target=worker)
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
                if command:
                    log.debug("Got message from Slack: {}")
                    log.debug('{} {} {}'.format(command, channel, user))
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
