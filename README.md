# sam-bot
Bot to create MISP events from data in Slack

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


 config.json example
 ~~~~shell{
	"slack":{
		"SLACK_BOT_TOKEN" : "xoxb-332250278039-yQQQom0PPoRz2QufGHlTnwg7"
	},
	"misp" : {
		"url" : "https://misp.test.local",
		"key" : "kTeD2m9yAHmuv9XYVB5vEAkrijTttwiO04LSQGAV"
	},
	"logging" : {
		"output_file" : "/var/log/this_is_the_log.log",
		"output_error_file": "/var/log/this_is_the_error_log.log"

	}
}
~~~~