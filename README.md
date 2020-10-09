# sam-bot
SAM Bot creates MISP events from data fed to it from Slack in a code snippet.

The following fields are accepted by SAMbot and will be added to the MISP event.
 
 - type: 
 - url: or kit: or creds: (it will also pickup any line with http or hxxp in it)
 - ip: 
 - domain: 
 - ip-dst:
 - ip-src:
 - from: or source-email: or email-source
 - subject:  
 - md5: 
 - sha1: 
 - sha256:
 - tag: 
 - hash|filename:
 
 Accepted fields for type are:
 
 - phish
 - malware
 - bec/scam
 - dump
 - apt
 
Tags that are accepted are 
 
 - TLP:white
 - TLP:green
 - TLP:amber
 - TLP:red  

### Example
~~~shell
type: malware
Url: http://bad.biz/r1/asda.exe
ip: 8.8.8.8
ip-dst: 8.8.8.8
ip-src: 1.1.1.1
domain: bad.biz
from: phish@avalanche.ru
subject: please transfer now
md5: c4c17055ea16183fbb6133b6e5cfb6f9
sha1: 17a5db6350140685d219f4f69dcc0e669a4f027e
sha256: 6b773f5367c1a6a108537b9ee17c95314158b1de0b5195eabb9a52eaf145b90a
hash|filename: 6b773f5367c1a6a108537b9ee17c95314158b1de0b5195eabb9a52eaf145b90a|asda.exe
tag: tlp:RED
~~~


## Installation requirements

#### Must use Python3

Run the following:
~~~~shell
pip3 install -r requirements.txt
~~~~

### Bot Configuration:
 - Add MISP URL and API key to config.json file
 - Add Slack bot token to config.json file
 - Add log name/location to config.json (Optional)

### MISP requirements:
Import the machinetag.json file as a new taxonomy 
~~~~shell
$ cd /var/www/MISP/app/files/taxonomies/
$ mkdir privatetaxonomy
$ cd privatetaxonomy
$ vi machinetag.json
$ paste contents
~~~~

### Taxonomies to be enabled at a minimum:
the bot requires that the following taxonomies are enable to run
 - TLP
 - IR8

If you don't specify a `logging` config, it'll default to putting logs in './logs/', which is the log volume for docker.

 config.json example
 ~~~~shell
{
    "slack":{
        "SLACK_BOT_OAUTH_TOKEN" : "xoxb-332250278039-yQQQom0PPoRz2QufGHlTnwg7",
        "SLACK_SIGNING_SECRET" : "sadfasdfasfasfasdfsadfasdfafasdfasdfasd"
    },
    "misp" : {
        "url" : "https://misp.test.local",
        "key" : "asdfasdfsadfasfsadfsadfsdfdsafasdfasfasfasdfasdfsadf"
    },
    "logging" : {
        "output_file" : "sambot.log",
        "output_error_file": "sambot_error.log"
    }
}
~~~~

# Development

Set up a slack app, follow instructions in the git repo here: https://github.com/slackapi/python-slack-events-api/tree/main/example

## Event Subscriptions

It needs to sub to the following events:

- message.channels
- file_created
- file_shared