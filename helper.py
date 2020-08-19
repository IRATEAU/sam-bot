from pprint import pprint 

def get_username(prog_username, slack_client, token):
	pprint('got %s as username' %prog_username)
	user_info = slack_client.users_info(token=token, user=prog_username)
	pprint('Got user info as :')
	if user_info['ok']:
		print('ok')
		if user_info.get('user') is not None:
			user = user_info['user']
			print('ok')
			if user.get('profile') is not None:
				profile = user['profile']
				if profile.get('display_name') is not None:
					print('ok')
					username = profile['display_name']
					print('Returning %s' %username)
					return username
