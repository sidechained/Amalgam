import requests

r = requests.get('http://en.wikipedia.org/wiki/United_States', stream=True)

for chunk in r.iter_content(1024):
	print 1
