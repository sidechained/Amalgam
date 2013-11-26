import requests

def gen():
    yield 'hi'
    yield 'there'

requests.post('http://www.wikipedia.org', data=gen())
