#!/usr/bin/env python3
import os
import time
import re
from slackclient import SlackClient
from pprint import pprint
import requests
import logging
from mispattruploader import *
import urllib3
import json
import pyjokes
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import os 
dir_path = os.path.dirname(os.path.realpath(__file__))
config_file = dir_path + '/config.json'
# instantiate Slack client
with open(config_file) as json_data_file:
    data = json.load(json_data_file)
token=data["slack"]["SLACK_BOT_TOKEN"]
slack_client = SlackClient(token)
misp = misp_custom(data['misp']['url'], data['misp']['key'])
if 'logging' in data:
    if 'output_file' in data['logging']:
        logging.basicConfig(
            filename=data['logging']['output_file'],
            level=logging.INFO, 
            format='%(asctime)s %(message)s', 
            datefmt='%d/%m/%Y %I:%M:%S %p')
else:
    logging.basicConfig(
        filename=dir_path + '/SAMbot.log',
        level=logging.INFO,
        format='%(asctime)s %(message)s', 
        datefmt='%d/%m/%Y %I:%M:%S %p')
# starterbot's user ID in Slack: value is assigned after the bot starts up
starterbot_id = None

# constants
RTM_READ_DELAY = 1 # 1 second delay between reading from RTM
EXAMPLE_COMMAND = "Tell a joke"
MENTION_REGEX = "^<@(|[WU].+?)>(.*)"

def parse_bot_commands(slack_events):
    """
        Parses a list of events coming from the Slack RTM API to find bot commands.
        If a bot command is found, this function returns a tuple of command and channel.
        If its not found, then this function returns None, None.
    """
    for event in slack_events:
        if event["type"] == "message" and "subtype" in event:
            if event["subtype"] == "file_share":
                url = event["file"]["url_private_download"]
                title = event["file"]["title"]
                if title == "Untitled":
                    strTitle = "#Warroom"
                else:
                    strTitle = "#Warroom " + title
                headers = {'Authorization': 'Bearer '+token}
                r = requests.get(url, headers=headers)
                content = r.content.decode("utf-8")
                e_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(event['event_ts'])))
                e_title = e_time + " - " + strTitle
                misp_response = misp.misp_send(0, content, e_title)
                return misp_response, None, event["channel"], event["user"]
        elif event["type"] == "message" and not "subtype" in event:
            logging.debug("Caught new method")
            user_id, message = parse_direct_mention(event["text"])
            logging.debug("User_id: %s \n Message: %s" %(user_id, message))
            logging.debug("starterbot_id : %s" %starterbot_id)
            if user_id == starterbot_id:
                return None, message, event["channel"], user_id
    return None, None, None, None

def respond(command, channel, user):
    # This is where you start to implement more commands!
    # Sends the response back to the channel
    slack_client.api_call(
        "chat.postEphemeral",
        channel=channel,
        text=command,
        user=user
    )

def parse_direct_mention(message_text):
    """
        Finds a direct mention (a mention that is at the beginning) in message text
        and returns the user ID which was mentioned. If there is no direct mention, returns None
    """
    matches = re.search(MENTION_REGEX, message_text)
    # the first group contains the username, the second group contains the remaining message
    return (matches.group(1), matches.group(2).strip()) if matches else (None, None)

def tell_a_joke(command, channel, user):
    """
        Executes bot command if the command is known
    """
    # Default response is help text for the user
    default_response = "Not sure what you mean. Try *{}*.".format(EXAMPLE_COMMAND)

    # Finds and executes the given command, filling in response
    response = None
    # This is where you start to implement more commands!
    if command.lower().startswith(EXAMPLE_COMMAND.lower()):
        response = pyjokes.get_joke(category='all') + " This joke has been Brought to you by pyjokes."
    # Sends the response back to the channel
    slack_client.api_call(
        "chat.postMessage",
        channel=channel,
        text=response or default_response
    )

if __name__ == "__main__":
    if slack_client.rtm_connect(with_team_state=False):
        logging.info("Starter Bot connected and running!")
        # Read bot's user ID by calling Web API method `auth.test`
        starterbot_id = slack_client.api_call("auth.test")["user_id"]

        while True:
            misp_response, smartass, channel, user = parse_bot_commands(slack_client.rtm_read())
            if misp_response:
                respond(misp_response, channel, user)
            elif smartass:
                print(smartass)
                tell_a_joke(smartass, channel, user)
            time.sleep(RTM_READ_DELAY)
    else:
        logging.info("Connection failed. Exception traceback printed above.")
