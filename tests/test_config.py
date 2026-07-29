from sam_bot import SamBotConfig


def test_config() -> None:
    testconfig = SamBotConfig.load("config.example.json")
    assert testconfig.slack.SLACK_BOT_OAUTH_TOKEN.get_secret_value() == "hunter2"
