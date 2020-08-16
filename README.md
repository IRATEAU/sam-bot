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
$ docker build -t sam-bot . 
$ docker run --env-file .env \
  -v $(pwd)/logs:/logs \
  -v $(pwd)/machinetag.json:/var/www/MISP/app/files/taxonomies/privatetaxonomy/machinetag.json
  sam-bot
~~~~

Or to run using already set environment variables
~~~~
$ docker run -v $(pwd)/logs:/logs -e SLACK_BOT_TOKEN -e MISP_URL -e MISP_KEY sam-bot
~~~~

### Bot Configuration:
For dev create the following in `.env` file in project root
~~~shell
SLACK_BOT_TOKEN=
MISP_URL=https://url/
MISP_KEY=
~~~
more info https://docs.docker.com/compose/env-file/

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


 config.json example
 ~~~~json
{
	"slack":{
		"SLACK_BOT_TOKEN": "xoxb-332250278039-yQQQom0PPoRz2QufGHlTnwg7"
	},
	"misp": {
		"url": "https://misp.test.local",
		"key": "kTeD2m9yAHmuv9XYVB5vEAkrijTttwiO04LSQGAV"
	},
	"logging": {
		"output_file": "/var/log/this_is_the_log.log",
		"output_error_file": "/var/log/this_is_the_error_log.log"

	}
}
~~~~
