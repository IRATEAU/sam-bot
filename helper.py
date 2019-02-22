from logging.config import dictConfig
import logging



class TonyTheHelper:
	def __init__(self, slackclient):
		self.slack_client = slackclient
		self.helper_logging = logging.getLogger('TonyTheHelper')
		self.helper_logging.info('Connected from TonyTheHelper')

	def print_help(self):
		response = """
		>Please see the accepted fields in the Github repo
		`https://github.com/IRATEAU/sam-bot/blob/master/README.md`
		"""
		return response

	def respond(self, command, channel, user):
	# This is where you start to implement more commands!
	# Sends the response back to the channel
		self.slack_client.api_call(
			"chat.postEphemeral",
			channel=channel,
			text=command,
			user=user
		)

	def respond_channel(self, command, channel):
		self.slack_client.api_call(
			"chat.postMessage",
			channel=channel,
			text=command
		)