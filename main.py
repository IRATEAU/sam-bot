from pprint import pprint
import flask
import threading
import helper
import slack
import os
import logging
import json
import slack.errors
from slackeventsapi import *
from logging.config import dictConfig
import requests
import time
import traceback
from mispattruploader import *

'''
You need to have an Event subscription enabled that points to the flask app
https://api.slack.com/apps/A012QE04RME/event-subscriptions?
https://api.slack.com/events-api#subscriptions
https://github.com/slackapi/python-slack-events-api
https://github.com/slackapi/python-slackclient/blob/master/tutorial/03-responding-to-slack-events.md
'''


dir_path = os.path.dirname(os.path.realpath(__file__))
config_file = dir_path + '/config.json'
# instantiate Slack client
output_error_file = ""
with open(config_file) as json_data_file:
	data = json.load(json_data_file)
token=data["slack"]["SLACK_BOT_OAUTH_TOKEN"]
secret = data['slack']['SLACK_SIGNING_SECRET']
if 'logging' in data:
	if 'output_file' in data['logging']:
		output_all_file = data['logging']['output_file']
	else:
		exit("Please include output_file in config")
	if 'output_error_file' in data['logging']:
		output_error_file = data['logging']['output_error_file']
else:
	output_all_file = dir_path + "/sambot.log"


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
			'filename': output_all_file,
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

if output_error_file != "":
	logging_config['handlers']['file_error'] = {
				'class': 'logging.handlers.RotatingFileHandler',
				'level': 'ERROR',
				'formatter': 'f',
				'filename': output_error_file,
				'mode': 'a',
				'maxBytes': 10485760,
				'backupCount': 5,
		}
	logging_config['root']['handlers'].append('file_error')

dictConfig(logging_config)

logger = logging.getLogger('SAMbot')
try: 
	misp = misp_custom(data['misp']['url'], data['misp']['key'], data['misp']['ssl'])
	logger.info("Connected to misp server successfully")
except Exception as e:
	logger.error('Exception Caught! FIX YOUR CONFIG')
	error = traceback.format_exc()
	logger.error(error)
	exit()

slack_signing_secret = secret
slack_events_adapter = SlackEventAdapter(slack_signing_secret, '/slack/events')
slack_bot_token = token
slack_client = slack.WebClient(slack_bot_token)
#pprint(dir(slack_client))
def file_handler(event):
	logger.info('got file from slack')
	#pprint(file_data)

	if "files" in event:
		for file in event["files"]: 
			if file["mode"] == "snippet":
				url = file["url_private_download"]
				title = file["title"]
				if title == "Untitled":
					strTitle = "#Warroom"
				else:
					strTitle = "#Warroom " + title
				headers = {'Authorization': 'Bearer '+ slack_bot_token}
				r = requests.get(url, headers=headers)
				content = r.content.decode("utf-8")
				e_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(event['event_ts'])))
				e_title = e_time + " - " + strTitle
				username = helper.get_username(event['user'], slack_client, slack_bot_token)
				logger.info(username)
				logger.info(e_title)
				logger.info(content)
				misp_response = misp.misp_send(0, content, e_title, username)
				slack_client.chat_postEphemeral(
					channel=event['channel'],
					text=misp_response,
					user=event['user']
				)


@slack_events_adapter.on('message')
def handle_message(event_data):
	logger.info('Got message from slack')
	logger.info(event_data)
	message = event_data['event']
	if message.get('files') is not None:

		file_info = message
		t = threading.Thread(target=file_handler, args=(file_info,))
		t.start()
		#file_handler(file_info)
		return flask.Response('', headers={'X-Slack-No-Retry': 1}), 200
	# if the incoming message contains 'hi', then respond with a 'hello message'
	if message.get('subtype') is None and 'hi' in message.get('text'):
		channel = message['channel']
		message = "Hello <@%s>! :tada:" % message['user']
		slack_client.chat_postMessage(channel=channel, text=message)
		return '', 200
@slack_events_adapter.on("error")
def error_handler(err):
	logger.info('got error from slack')
	print("ERROR: " + str(err))

slack_events_adapter.start(port=3000, host='0.0.0.0')
