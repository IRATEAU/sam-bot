import slack
import slack.errors
import slackeventsapi
'''
You need to have an Event subscription enabled that points to the flask app
https://api.slack.com/apps/A012QE04RME/event-subscriptions?
https://api.slack.com/events-api#subscriptions
https://github.com/slackapi/python-slack-events-api
https://github.com/slackapi/python-slackclient/blob/master/tutorial/03-responding-to-slack-events.md
'''
slack_signing_secret = '<SIGNING_SECRET>'
slack_events_adapter = SlackEventAdapter(slack_signing_secret, '/slack/events')
slack_bot_token = '<BOT_OAUTH_TOKEN>'
slack_client = slack.WebClient(slack_bot_token)
@slack_events_adapter.on('message')
def handle_message(event_data):
    message = event_data['event']
    # if the incoming message contains 'hi', then respond with a 'hello message'
    if message.get('subtype') is None and 'hi' in message.get('text'):
        channel = message['#sam-bot-dev']
        message = "Hello <@%S>! :tada:" % message['user']
        slack_client.api_call("chat.postMessage", channel=channel, text=message)
@slack_events_adapter.on("error")
def error_handler(err):
    print("ERROR: " + str(err))
slack_events_adapter.start(port=3000)