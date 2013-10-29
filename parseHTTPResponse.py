#!/usr/bin/env python

# Parse HTTP response

from StringIO import StringIO
from httplib import HTTPResponse

class FakeSocket(StringIO):
    def makefile(self, *args, **kw):
        return self

def httpparse(fp):
    socket = FakeSocket(fp.read())
    response = HTTPResponse(socket)
    response.begin()

    return response

if __name__ == "__main__":
    from os import popen

    with open ("/Users/grahambooth/Desktop/Amalgam/systemç design/session3_decoding_packets_manually/packetç examination/http/404notfound", "r") as myfile:
        response=httpparse(myfile.read())
        print response.getheaders()
        print response.msg
        print response.status

