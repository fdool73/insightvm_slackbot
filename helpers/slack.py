import re
from random import choice


EXAMPLE_COMMAND = "scan"
MENTION_REGEX = "^<@(|[WU].+?)>(.*)"


def extract_ips(input_string):
    """
    Regex function to parse text and return a list of IPs int the text.
    """
    # Regex to parse IP addresses
    ip_regex = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[?0-5]|2[0-4][0-9]|[01?]?[0-9][0-9]?)"
    ip_matches = re.findall(ip_regex, input_string)
    return ip_matches if ip_matches else None


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
    response = "<@{}> Not sure what you mean. Try *{}*.".format(user, EXAMPLE_COMMAND)

    # Test to see if IPs are in the command
    ip_list = extract_ips(command)

    # Finds and executes the given command, filling in response
    # Check if the IP list exists and is not longer than 5 IPs
    if (command.startswith(EXAMPLE_COMMAND) and ip_list and len(ip_list) > 5):
        response = 'Please limit your ad hoc scan to 5 or less IPs.'

    # Check if list has proper list of IPs and schedule scan
    elif ip_list and command.startswith(EXAMPLE_COMMAND):
        response = "<@{}> Scheduling scan for: {}.".format(user, ','.join(ip_list))
        response += '  :partyparrot:'

        # Write data to queue
        queue.put({'command': command,
                   'ip_list': ip_list,
                   'channel': channel,
                   'user': user})

    # Check if no IPs were supplied and show usage
    elif command.startswith(EXAMPLE_COMMAND):
        response = "<@{}> Sure...what IPs would you like to scan?\n".format(user)
        response += 'Use `scan <IP Address>`'

    return response
