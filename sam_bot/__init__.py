from pathlib import Path
from typing import Dict, Self
import logging
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class MISPConfig(BaseSettings):
    url: str
    key: SecretStr
    ssl: bool = Field(True)


class SlackConfig(BaseSettings):
    SLACK_BOT_OAUTH_TOKEN: SecretStr = Field()
    SLACK_SIGNING_SECRET: SecretStr = Field()

    model_config = SettingsConfigDict(env_prefix="")

    @model_validator(mode="before")
    def validate_slack_config(cls, values: Dict[str, str]) -> Dict[str, str]:
        if not values.get("SLACK_BOT_OAUTH_TOKEN"):
            raise ValueError("SLACK_BOT_OAUTH_TOKEN is required")
        if not values.get("SLACK_SIGNING_SECRET"):
            raise ValueError("SLACK_SIGNING_SECRET is required")
        return values


class LoggingConfig(BaseSettings):
    output_file: str = Field("./logs/sambot.log")
    output_error_file: str = Field("./logs/sambot_error.log")

    @classmethod
    def default(cls) -> Self:
        return cls.model_validate({})


class SamBotConfig(BaseSettings):
    slack: SlackConfig
    misp: MISPConfig
    testing: bool = False
    logging: LoggingConfig = Field(default_factory=LoggingConfig.default)
    port: int = Field(3000, ge=1024, le=65535)
    host: str = Field("0.0.0.0")

    @classmethod
    def load(cls, filename: str = "config.json") -> Self:
        filepath = Path(filename)
        if filepath.exists():
            return cls.model_validate_json(filepath.read_text())
        else:
            logger = logging.getLogger("sam_bot")
            logger.warning("No config file found, using default settings.")
            return cls.model_validate({})
