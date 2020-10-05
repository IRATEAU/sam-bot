'''
sam-bot

You need to have an Event subscription enabled that points to the flask app
https://api.slack.com/apps/A012QE04RME/event-subscriptions?
https://api.slack.com/events-api#subscriptions
https://github.com/slackapi/python-slack-events-api
https://github.com/slackapi/python-slackclient/blob/master/tutorial/03-responding-to-slack-events.md
'''

import logging
from logging.config import dictConfig
import json
import os
import sys
import time
import traceback
import threading

import requests
import flask
import slack
import slack.errors
from slackeventsapi import SlackEventAdapter
from mispattruploader import MispCustomConnector

import helper

dir_path = os.path.dirname(os.path.realpath(__file__))
config_file = dir_path + '/config.json'

# parse config file
with open(config_file) as json_data_file:
    try:
        data = json.load(json_data_file)
    except json.decoder.JSONDecodeError as error:
        sys.exit(f"Couldn't parse config.json: {error}")


if 'logging' in data:
    # default to sambot.log in log dir next to script if it's not set
    LOGFILE_DEFAULT = data['logging'].get('output_file', f"{dir_path}/logs/sambot.log")
    # default to sambot_error.log in log dir next to script if it's not set
    LOGFILE_ERROR = data['logging'].get('output_error_file', f"{dir_path}/logs/sambot_error.log")
else:
    # defaults
    LOGFILE_DEFAULT = "./logs/sambot.log"
    LOGFILE_ERROR = "./logs/sambot_error.log"

logging_config = dict(
    version = 1,
    formatters = {
        'f': {'format':
              '%(asctime)s - %(name)s - %(levelname)s - %(message)s'}
        },
    handlers = {
        'Stream': {'class': 'logging.StreamHandler',
              'formatter': 'f',
              'level': 'DEBUG'
        },
        'file_all': {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'DEBUG',
            'formatter': 'f',
            'filename': LOGFILE_DEFAULT,
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
        },
    },
    root = {
        'handlers': ['Stream', 'file_all'],
        'level': 'DEBUG',
        },
)


logging_config['handlers']['file_error'] = {
            'class': 'logging.handlers.RotatingFileHandler',
            'level': 'ERROR',
            'formatter': 'f',
            'filename': LOGFILE_ERROR,
            'mode': 'a',
            'maxBytes': 10485760,
            'backupCount': 5,
    }
logging_config['root']['handlers'].append('file_error')

dictConfig(logging_config)

logger = logging.getLogger('SAMbot')

# connecting to MISP
try:
    misp = MispCustomConnector(misp_url=data['misp']['url'],
                       misp_key=data['misp']['key'],
                       misp_ssl=data.get('misp', {}).get('ssl', True), # default to using SSL
                       )
    logger.info("Connected to misp server successfully")
# Who knows what kind of errors PyMISP will throw?
#pylint: disable=broad-except
except Exception:
    logger.error('Failed to connect to MISP:')
    logger.error(traceback.format_exc())
    sys.exit()

# config file - slack section
if not data.get('slack'):
    logger.error("No 'slack' config section, quitting.")
    sys.exit()

MISSED_SLACK_KEY = False
for key in ('SLACK_BOT_OAUTH_TOKEN', 'SLACK_SIGNING_SECRET'):
    if key not in data.get('slack'):
        MISSED_SLACK_KEY = True
        logger.error("Couldn't find %s in config.json slack section, going to quit.", key)
if MISSED_SLACK_KEY:
    sys.exit()
else:
    slack_bot_token = data['slack']['SLACK_BOT_OAUTH_TOKEN']
    slack_signing_secret = data['slack']['SLACK_SIGNING_SECRET']


slack_events_adapter = SlackEventAdapter(slack_signing_secret, '/slack/events')


def file_handler(event):
    """ handles files from slack client """
    logger.info('got file from slack')

    for file_object in event.get('files'):
        if file_object.get('mode') == "snippet":
            url = file_object.get('url_private_download')
            title = file_object.get('title')
            if title == 'Untitled':
                event_title = '#Warroom'
            else:
                event_title = f"#Warroom {title}"
            headers = {'Authorization': f"Bearer {slack_bot_token}"}

            response = requests.get(url, headers=headers)
            response.raise_for_status()

            # TODO: this might just need to be response.text
            content = response.content.decode("utf-8")

            e_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(event['event_ts'])))
            e_title = f"{e_time} - {event_title}"
            username = helper.get_username(event.get('user'), slack_client, slack_bot_token)
            logger.info(username)
            logger.info(e_title)
            logger.info(content)
            misp_response = misp.misp_send(0, content, e_title, username)
            slack_client.chat_postEphemeral(
                channel=event.get('channel'),
                text=misp_response,
                user=event.get('user'),
            )

@slack_events_adapter.on('message')
def handle_message(event_data):
    """ slack message handler """
    logger.info('Got message from slack')
    logger.info(event_data)
    message = event_data.get('event')
    if message.get('files'):
        file_info = message
        thread_object = threading.Thread(target=file_handler, args=(file_info,))
        thread_object.start()
        #file_handler(file_info)
        return_value = flask.Response('', headers={'X-Slack-No-Retry': 1}), 200

    # if the incoming message contains 'hi', then respond with a 'hello message'
    elif message.get('subtype') is None and 'hi' in message.get('text'):
        channel = message['channel']
        message = "Hello <@%s>! :tada:" % message['user']
        slack_client.chat_postMessage(channel=channel, text=message)
        return_value = '', 200
    # shouldn't get here, but return a 403 if you do.
    return_value = 'Unhandled message type', 403
    return return_value

@slack_events_adapter.on("error")
def error_handler(err):
    """ slack error message handler """
    logger.error("Slack error: %s", str(err))

if __name__ == '__main__':
    slack_client = slack.WebClient(slack_bot_token)
    slack_events_adapter.start(port=3000, host='0.0.0.0')
