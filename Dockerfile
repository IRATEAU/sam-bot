FROM python:3.7-slim-buster

RUN apt-get update && \
    apt-get upgrade && \
    rm -rf /var/lib/apt/lists/*

COPY . /sam-bot

WORKDIR /sam-bot

RUN pip3 install -r requirements.txt

RUN useradd sambot
RUN mkdir -p /logs && chown sambot /logs

USER sambot

ENTRYPOINT ["python", "/sam-bot/SAMbot.py"]