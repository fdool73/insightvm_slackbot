import itertools
from joblib import Parallel, delayed
import re
from random import choice
import time

import helpers


EXAMPLE_COMMAND = "scan"
MENTION_REGEX = "^<@(|[WU].+?)>(.*)"


def extract_ips(input_string):
    """
    Regex function to parse text and return a list of IPs in the text.
    """
    # Regex to parse IP addresses
    ip_matches = []
    ip_regex = '(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[?0-5]|2[0-4][0-9]|[01?]?[0-9][0-9]?(?!\w))'
    ip_matches = re.findall(ip_regex, input_string)
    return ip_matches


def extract_hostnames(input_string):
    """
    Regex function to parse text and return a list of hostnames in the text.
    """
    # Regex to parse hostnames
    hostname_matches = []
    hostname_regex = '(?:^|(?<=\s))(?:[a-zA-Z0-9\-]+\.)+(?:[a-zA-Z])+(?:(?=\s|(?=[,])|(?=$)))'
    hostname_matches = re.findall(hostname_regex, input_string)
    dedup = set(hostname_matches)
    hostname_matches = list(dedup)
    return hostname_matches


def get_gif():
    '''
    Select a random GIF from this list of SFW images
    '''
    gif_list = [
        'http://gph.is/2DgKb0M',
        'http://gph.is/1aR7NWq',
        'http://gph.is/1IH3RW6',
        'http://gph.is/22ziZPj',
        'http://gph.is/15RTH5O',
        'http://gph.is/1sCtWoD',
        'http://gph.is/28MUy1t',
        'http://gph.is/2oEbigY'
    ]

    return choice(gif_list)


def parse_bot_commands(slack_events, bot_id):
    """
        Parses a list of events coming from the Slack RTM API to find bot commands.
        If a bot command is found, this function returns a tuple of command and channel.
        If its not found, then this function returns None, None.
    """

    for event in slack_events:
        if event["type"] == "message" and "subtype" not in event:
            user_id, message = parse_direct_mention(event["text"])
            if user_id == bot_id:
                return message, event["channel"], event['user']
    return None, None, None


def parse_direct_mention(message_text):
    """
        Finds a direct mention (a mention that is at the beginning) in message
        text and returns the user ID which was mentioned. If there is no direct
        mention, returns None
    """
    matches = re.search(MENTION_REGEX, message_text)
    # the first group contains the username, the second group contains the remaining message
    return (matches.group(1), matches.group(2).strip()) if matches else (None, None)


def handle_command(command, channel, user, queue):
    """
    Executes bot command if the command is known. Checks message for valid
    IPs and then returns a message to the user if there is an error condition
    (too many IPs or no IPs).  If the IP list is valid queue the scan task and
    return message to user stating the scan is being scheduled.
    """

    # Default response is help text for the user
    response = "<@{}> Not sure what you mean. Try *@nexpose_bot scan <IP/Hostname>*.".format(user)

    # Test to see if IPs are in the command
    ip_list = extract_ips(command)
    hostname_list = extract_hostnames(command)
    target_list = ip_list + hostname_list

    # Finds and executes the given command, filling in response
    # Check if the IP list exists and is not longer than 5 IPs
    if (command.startswith(EXAMPLE_COMMAND) and target_list and len(target_list) > 5):
        response = 'Please limit your ad hoc scan to 5 or less targets.'

    # Check if list has proper list of IPs and schedule scan
    elif target_list and command.startswith(EXAMPLE_COMMAND):
        response = "<@{}> Scheduling scan for: {}.".format(user, ','.join(target_list))
        response += '  :partyparrot:'

        # Write data to queue
        queue.put({'command': command,
                   'target_list': target_list,
                   'channel': channel,
                   'user': user})

    # Check if no IPs were supplied and show usage
    elif command.startswith(EXAMPLE_COMMAND):
        response = "<@{}> Sure...what IPs would you like to scan?\n".format(user)
        response += 'Use `scan <IP Address/Hostname>`'

    return response


def worker(scan_tasker_queue, slack_client, log):
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

        # Determine site membership for the requested targets
        # List placeholder, parrallel function returns a list of outputs
        site_asset_set = []
        log.info("Getting list of all sites.")
        # First get all site IDs since asset site membership is not exposed
        # anywhere in the API.
        sites = helpers.retrieve_all_site_ids()
        log.info('Retrieving target lists, this may take a while...')

        # Run site_membership in parrallel, this is the biggest bottleneck
        # Take the target set and see if those assets are included targets in
        # EVERY site.  Not pretty, but necesary given API limitations.
        site_asset_list = Parallel(n_jobs=10, backend="threading")(
            delayed(helpers.site_membership)(site, item['target_list'])
            for site in sites.keys())

        # Dedup and cleanup.
        site_asset_set = set(list(itertools.chain(*site_asset_list)))
        log.debug('List returned from parrallel processing: {}'.format(site_asset_set))

        # Parse site and address to get final site to scan, assets to scan,
        # and assets that will not be scanned due to not existing.
        target_set = set()
        site_set = set()
        no_scan_set = set()
        # Get actual targets and site
        for site_asset_pair in site_asset_set:
            if site_asset_pair[0] == 0:
                no_scan_set.add(site_asset_pair[1])
            target_set.add(site_asset_pair[1])
            site_set.add(site_asset_pair[0])
            no_scan_set = set(item['target_list']) - target_set

        log.info('Site set: {}'.format(site_set))
        log.info('Target set: {}'.format(target_set))
        log.info('No-scan set: {}'.format(no_scan_set))

        # Check if assets reside in more than one site, prompt for additional
        # info if needed.  All assets should/must reside in one common site.
        # Counting on InsightVM to handle different site errors server-side.

        # If `site_set` has more than one site, then we know that the assets to
        # be scanned either reside in multiple sites or any single asset has
        # multiple site memberships.  We cannot scan in this situation and must
        # Get a site ID. Logic below responds with that guidance and parses it
        # if it exists.
        scan_id = None

        # Assets in multiple sites but site ID provided.
        if len(site_set) > 1 and 'site id:' in item['command'].lower():
            try:
                scan_id = helpers.adhoc_site_scan(target_set, int(item['command'].split(':')[1]))
                message = "<@{}> Scan ID: {} started".format(item['user'], scan_id)
            except SystemError as e:
                message = "<@{}> Scan ID: {} produced an error".format(item['user'])
                message += e
        # Assets in multiple sites but NO site ID provided.
        elif len(site_set) > 1:
            message = '<@{}> Assets exist in multiple sites ({}). '
            message += 'Please re-run command with '
            message += '`@nexpose_bot scan <IPs> site id:<ID>``'
            message = message.format(item['user'], site_set)
        # All assets do not exist in Nexpose
        elif len(site_set) == 0:
            message = '<@{}> scan for {} *failed*.'
            message += '  Device(s) do not exist in insightvm :confounded:'
            message += ' Device must have been scanned previously through a normal scan.'
            message = message.format(item['user'], item['target_list'])
        # All assets live in one site
        else:
            try:
                scan_id = helpers.adhoc_site_scan(target_set, site_set.pop())
                message = "<@{}> Scan ID: {} started".format(item['user'], scan_id)
            except SystemError as e:
                message = "<@{}> Scan produced an error".format(item['user'])
                message += e

        # Indicate if some assets were not scanned due to no existing in Nexpose.
        if no_scan_set:
            message += 'These hosts do not exist in InsightVM, unable to scan: {}'.format(no_scan_set)

        # Respond to Slack with result
        log.info(message)
        slack_client.api_call(
            "chat.postMessage",
            channel=item['channel'],
            text=message,
            as_user=True
        )

        # Monitor scan for completion, simply break if scan has failed or other
        # error. Only do this if a scan_id was returned indicating a scan started.
        while True and scan_id is not None:
            time.sleep(60)
            scan = helpers.retrieve_scan_status(scan_id)
            log.debug("Current statuts for Scan {}: {}".format(scan_id, scan['status']))
            if scan['status'] in ['running', 'integrating', 'dispatched']:
                continue
            else:
                break

        # Gather scan details
        if scan['status'] == 'finished':
            message = "<@{}> Scan ID: {} finished for {} at {}\n"
            message += "*Scan Duration*: {} minutes\n {}\n"
            message += "Report is being generated at https://nexpose.secops.rackspace.com/report/reports.jsp "
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
            text=message,
            as_user=True
        )

        log.debug('Worker done.')
        scan_tasker_queue.task_done()
