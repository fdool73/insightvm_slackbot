# Nexpose Slack Bot

![nexpose_bot](nexpose_bot.png)

# nexpose_slackbot
Slackbot to automate ad-hoc scanning and reporting in Nexpose.  In Slack, simply send a message like `@nexpose_bot scan 192.18.1.1` and see the bot schedule the scan, run it, and report back the results.  You can also just set up a direct chat with the bot if you don't want to spam your channel.  Use the same syntax to schedule a scan.

# Getting Started

##Create A Bot In Slack
This guide sums bot creation up pretty simply. https://www.fullstackpython.com/blog/build-first-slack-bot-python.html


### Set up virtual environment
```bash
virtualenv -p /usr/bin/python3 .venv
source .venv/bin/activate
pip install -r requirements/common.txt
# For Dev
pip install -r requirements/dev.txt
```

### Install helpers package
```bash
cd insight-scripts/
python setup.py install
```

### Update credentials and options for the bot.
```bash
cd keys/
cp secrets.json.empty secrets.json
vi secrets.json
```
All values are required.

`log_level` higher is LESS verbose. Must be 1-5 inclusive.
`log_location` is the `path/to/logfile` where you want to log.
`workers` is the way that we rate limit scans initiated by the bot. Use this setting to limit the number of concurrent scans the bot can invoke.

### Run
python nexpose_bot.py

# TODO
- Parallelize the request to Nexpose for asset site membership.  This will be OBE if the API v3 Asset object ever includes the site membership list.
- Validate user has Nexpose access (to site/asset) - may require global admin user as slackbot.
