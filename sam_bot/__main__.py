"""
sam-bot

You need to have an Event subscription enabled that points to the flask app
https://api.slack.com/apps/A012QE04RME/event-subscriptions?
https://api.slack.com/events-api#subscriptions
https://github.com/slackapi/python-slack-events-api
https://github.com/slackapi/python-slackclient/blob/master/tutorial/03-responding-to-slack-events.md
"""

import asyncio
import logging
from logging.config import dictConfig
import os
import sys
import time
import traceback
import threading
from typing import Any, Dict, List, Optional, Tuple, Union

import click
import requests
import flask
from slack_sdk.web.async_client import AsyncWebClient
# from slack_sdk.socket_mode import SocketModeClient

from slack_sdk.web.async_slack_response import AsyncSlackResponse
from slackeventsapi import SlackEventAdapter  # type: ignore[import-untyped]
from sam_bot import SamBotConfig
from sam_bot.misp import MispCustomConnector

dir_path = os.path.dirname(os.path.realpath(__file__))
# config_file = dir_path + "./config.json"

# parse config file
CONFIG = SamBotConfig.load()

slack_client = AsyncWebClient(
    token=CONFIG.slack.SLACK_BOT_OAUTH_TOKEN.get_secret_value()
)
logging_config: Dict[str, Any] = dict(
    version=1,
    formatters={
        "f": {"format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s"}
    },
    handlers={
        "Stream": {
            "class": "logging.StreamHandler",
            "formatter": "f",
            "level": "DEBUG",
        },
        "file_all": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "f",
            "filename": CONFIG.logging.output_file,
            "mode": "a",
            "maxBytes": 10485760,
            "backupCount": 5,
        },
    },
    root={
        "handlers": ["Stream", "file_all"],
        "level": "DEBUG",
    },
)


logging_config["handlers"]["file_error"] = {
    "class": "logging.handlers.RotatingFileHandler",
    "level": "ERROR",
    "formatter": "f",
    "filename": CONFIG.logging.output_error_file,
    "mode": "a",
    "maxBytes": 10485760,
    "backupCount": 5,
}
logging_config["root"]["handlers"].append("file_error")

dictConfig(logging_config)

logger = logging.getLogger("SAMbot")

# connecting to MISP
try:
    misp_object = MispCustomConnector(
        misp_url=CONFIG.misp.url,
        misp_key=CONFIG.misp.key.get_secret_value(),
        misp_ssl=CONFIG.misp.ssl,
    )
    logger.info(
        "Connected to MISP server successfully at %s (tls=%s)",
        CONFIG.misp.url,
        CONFIG.misp.ssl,
    )
# Who knows what kind of errors PyMISP will throw?
# pylint: disable=broad-except
except Exception:
    logger.error("Failed to connect to MISP:")
    logger.error(traceback.format_exc())
    sys.exit(1)


slack_events_adapter = SlackEventAdapter(
    CONFIG.slack.SLACK_SIGNING_SECRET.get_secret_value(), endpoint="/slack/events"
)


async def get_username(
    prog_username: str, slack_client: AsyncWebClient, token: str
) -> Union[str, bool]:
    """pulls the slack username from the event"""
    logger.debug("Got %s as username", prog_username)
    user_info = await slack_client.users_info(token=token, user=prog_username)
    if user_info.get("ok"):
        user = user_info.get("user")
        if user is not None:
            profile = user.get("profile")
            if profile is not None:
                username: Optional[str] = profile.get("display_name")
                if username is not None:
                    logger.debug("Returning %s", username)
                    return username
    return False


def file_handler(event: Dict[str, Any]) -> None:
    """handles files from slack client"""
    files = event.get("files", list())

    if not files:
        logger.warning("Got 0 files from slack, bailing.")
        return

    logger.info("got %s files from slack", len(files))
    for file_object in files:
        if file_object.get("mode") == "snippet":
            url = file_object.get("url_private_download")
            title = file_object.get("title")
            if title == "Untitled":
                event_title = "#Warroom"
            else:
                event_title = f"#Warroom {title}"
            headers = {
                "Authorization": f"Bearer {CONFIG.slack.SLACK_BOT_OAUTH_TOKEN.get_secret_value()}"
            }

            response = requests.get(url, headers=headers)
            response.raise_for_status()

            # TODO: this might just need to be response.text
            content = response.content.decode("utf-8")

            e_time = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(float(event["event_ts"]))
            )
            e_title = f"{e_time} - {event_title}"
            loop = asyncio.new_event_loop()
            userid = event.get("user", "-")
            username = loop.run_until_complete(
                get_username(
                    userid,
                    slack_client,
                    CONFIG.slack.SLACK_BOT_OAUTH_TOKEN.get_secret_value(),
                )
            )
            if username is False:
                username = "Unknown User"
            misp_response = misp_object.misp_send(0, content, e_title, str(username))
            post_result = loop.run_until_complete(
                slack_client.chat_postEphemeral(
                    channel=event["channel"],
                    text=misp_response,
                    user=event["user"],
                )
            )
            logger.debug("Posted ephemeral message to slack: %s", post_result)


# untyped decorator leads to mypy warning, so ignore it
@slack_events_adapter.on("message")  # type: ignore[misc]
def handle_message(event_data: Dict[str, Any]) -> Tuple[flask.Response, int]:
    """slack message handler"""
    logger.info("handle_message Got message from slack")
    logger.info(event_data)
    message = event_data.get("event")
    if message is None:
        logger.error("No message found in event data, bailing.")
        return flask.Response("No message found"), 400
    logger.info(f"Message type: {message.get('type')}")
    logger.info(f"Message text: {message.get('text')}")
    if message.get("files"):
        logger.info("Files message")
        file_info = message
        thread_object = threading.Thread(target=file_handler, args=(file_info,))
        thread_object.start()
        return_value = flask.Response("", headers={"X-Slack-No-Retry": "1"}), 200
    # elif str(message.get('type')) == 'message' and str(message.get('text')) == 'sambot git update':
    #     logger.info(f"Git pull message from {message.get('user')} in {message.get('channel')}")

    #     response = f"Doing a git pull now..."
    #     slack_client.chat_postMessage(channel=message.get('channel'), text=response)

    #     git_repo = git.cmd.Git(os.path.dirname(os.path.realpath(__file__)))
    #     git_result = git_repo.pull()

    #     response = f"Done!\n```{git_result}```"
    #     slack_client.chat_postMessage(channel=message.get('channel'), text=response)

    #     return_value = '', 200
    # if the incoming message contains 'hi', then respond with a 'hello message'
    elif message.get("subtype") is None and "hi" in message.get("text"):
        logger.info(
            f"Hi message from {message.get('user')} in {message.get('channel')}"
        )
        response = f"Hello <@{message.get('user')}>! :tada:"
        channel = message.get("channel", None)
        if channel is None:
            logger.error("No channel found in message, can't send response.")
            return_value = flask.Response("No channel found"), 400
            return return_value
        asyncio.new_event_loop().run_until_complete(
            slack_client.chat_postMessage(channel=channel, text=response)
        )
        return_value = flask.Response(""), 200
    else:
        logger.info("Message fell through, returning 403...")
        # shouldn't get here, but return a 403 if you do.
        return_value = flask.Response("Unhandled message type"), 403
    return return_value


# untyped decorator, so ignore the type checking for this function
@slack_events_adapter.on("error")  # type: ignore[misc]
def error_handler(err: Exception) -> None:
    """slack error message handler"""
    logger.error("Slack error: %s", str(err))


async def find_channel_id(
    slack_client: AsyncWebClient, channel_name: str = "_autobot"
) -> Union[str, bool]:
    """returns the channel ID of the channel"""
    conversations_list: AsyncSlackResponse = await slack_client.conversations_list()
    channels: Optional[list[Dict[str, Any]]] = conversations_list.get("channels")
    if channels is None:
        logger.error("Couldn't find channels in conversations_list, bailing.")
        return False
    for channel in channels:
        if channel.get("name") == channel_name:
            channel_id: Optional[str] = channel.get("id")
            if channel_id is None:
                logger.error("Couldn't find channel id for %s, bailing.", channel_name)
                return False
            logger.debug(f"found channel id for {channel_name}: {channel_id}")
            return channel_id
    return False


async def main(show_config: bool) -> None:
    if show_config:
        print(CONFIG.model_dump_json(indent=4))
        return

    if CONFIG.testing:
        bot_channel = await find_channel_id(slack_client, "_autobot")
        if isinstance(bot_channel, bool):
            if not bot_channel:
                logger.error("Couldn't find _autobot channel, quitting.")
                sys.exit(1)
            else:
                logger.error("Unknown error finding _autobot channel, quitting.")
                sys.exit(1)
        await slack_client.conversations_join(channel=bot_channel)
        # slack_client.chat_postMessage(
        #     channel=bot_channel, text="I've starting up in test mode!"
        # )
        logger.debug("I've started up in test mode...")

    conversations_list = await slack_client.conversations_list()
    channels: List[AsyncSlackResponse] = conversations_list.get("channels", list())
    for channel in channels:
        logger.debug("%s - %s", channel["id"], channel["name"])
    slack_events_adapter.start(port=CONFIG.port, host=CONFIG.host)


@click.command()
@click.option("--show-config", is_flag=True, help="Show the current configuration.")
def run(show_config: bool) -> None:
    try:
        loop = asyncio.get_event_loop()
        loop.run_until_complete(main(show_config))
    except Exception as error:
        logger.error("An error occurred while running the bot: %s", str(error))
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    run()
