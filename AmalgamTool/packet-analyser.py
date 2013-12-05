#!/usr/bin/python

# TODO:
# DONE: fix ends (packet length doesn't add up, chunked end packet not always received)
# find out why sometimes the body seems to be encryted
# body search trigger (parse as you go) - pass in searchTerm
# what happens when transfers stop half way through?

# TOFIX:
# messages continue to be sent even after stop

import sys
import string
import socket
import time
import re
from BaseHTTPServer import BaseHTTPRequestHandler
from httplib import HTTPResponse
from StringIO import StringIO
from threading import Thread
from OSC import OSCClient, OSCMessage, OSCServer, OSCClientError

import pcapy
from pcapy import findalldevs, open_live
import impacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

# classes

class HTTPRequest(BaseHTTPRequestHandler):
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message

class FakeSocket(StringIO):
    def makefile(self, *args, **kw):
        return self
    
class DecoderThread(Thread):
    def __init__(self, pcapObj):
        self.searchTerm = 'commands'
        self.hostDict = {}
        self.flowDict = {}
        self.arbitraryChunkedLength = 30000 # as length of chunked tranfers can not be measured, we will provide an artibrary length for now
        # OSC functionality (multicasting for now)
        sendAddress = '127.0.0.1', 57120
        self.oscClient=OSCClient()
        self.oscClient.connect(sendAddress)
        # Query the type of the link and instantiate a decoder accordingly.
        datalink = pcapObj.datalink()
        if pcapy.DLT_EN10MB == datalink:
            self.decoder = EthDecoder()
        elif pcapy.DLT_LINUX_SLL == datalink:
            self.decoder = LinuxSLLDecoder()
        else:
            raise Exception("Datalink type not supported: " % datalink)
        self.pcap = pcapObj
        Thread.__init__(self)

    def run(self):
        # Sniff ad infinitum.
        # PacketHandler shall be invoked by pcap for every packet.
        self.pcap.loop(0, self.packetHandler)
            
    def packetHandler(self, hdr, data):
        # Use the ImpactDecoder to turn the rawpacket into a hierarchy of ImpactPacket instances.
        eth = self.decoder.decode(data)
        ip = eth.child()
        tcp = ip.child()
        src = (ip.get_ip_src(), tcp.get_th_sport() )
        dst = (ip.get_ip_dst(), tcp.get_th_dport() )
        self.detectHTTP(tcp, src, dst)

    def detectHTTP(self, tcp, src, dst):
        packetString = tcp.get_data_as_string()
        srcIp = src[0]
        dstIp = dst[0]
        self.detectRequestOrNewResponseOrExistingResponse(packetString, src, dst, tcp)
        
    def detectRequestOrNewResponseOrExistingResponse(self, packetString, src, dst, tcp):
        request = HTTPRequest(packetString)
        if request.error_code is None: # detect request
            self.parseRequest(request, src, dst)
        elif packetString[:8] == "HTTP/1.1": # detect response
            # only pass if a request was sent
            flowKey = (src, dst)
            if flowKey in self.hostDict:
                self.parseNewResponse(packetString, src, dst, tcp)
        else:
            flowKey = (src, dst)
            if flowKey in self.flowDict: # continue if packet is a continuation of an existing response
                body = packetString # with an existing response the body is the entire packetstring
                self.parseExistingResponse(flowKey, body, src, dst, tcp)

    def parseRequest(self, request, src, dst):
        if request.command == 'GET' and request.request_version == 'HTTP/1.1' and 'host' in request.headers: # sometimes get header has no host
            # store the host and path related to this request by unique key for later lookup:
            self.hostDict[(dst, src)] = {}
            self.hostDict[(dst, src)]['host'] = request.headers['host']
            self.hostDict[(dst, src)]['path'] = request.path

    def parseNewResponse(self, packetString, src, dst, tcp):
        responseCode = packetString[9:12]
        if responseCode == '200': # just okay responses for now        
            if '\r\n\r\n' in packetString: # only proceed if the response has a body
                bodyIndex = packetString.index('\r\n\r\n') + 4
                body = packetString[bodyIndex:]
                socket = FakeSocket(packetString)
                response = HTTPResponse(socket)
                response.begin()
                headerArray = response.getheaders()
                for item in headerArray:
                    flowKey = (src, dst)
                    if item[0] == 'content-type' and 'text/html' in item[1]: # accept any kind of text content
                        for item in headerArray:
                            if item[0] == 'content-length':
                                length = int(item[1])
                                if length is not 0:
                                    self.parseFixedLengthResponse(flowKey, body, length, src, dst, tcp, responseCode)
                                else:
                                    print "warning, content-length is zero!"
                    elif item[0] == 'transfer-encoding' and item[1] == 'chunked':
                        print 'found chunked'
                        self.parseChunkedResponse(flowKey, body, src, dst, tcp, responseCode)
            else:
                print "body not found"

    def parseFixedLengthResponse(self, flowKey, body, length, src, dst, tcp, responseCode):
        self.flowDict[flowKey] = {'body': body, 'type': 'fixedLength', 'length': length}
        self.doStart(flowKey, body, src, dst, tcp, responseCode, 'fixedLength')
        contentLength = self.flowDict[flowKey]['length']
        progress = float(len(body)) / float(contentLength)
        packetContentLength = progress
        searchResults = self.bodySearch(body, contentLength)
        self.sendInfoAboutThisPacket(body, progress, packetContentLength, searchResults)  

    def parseChunkedResponse(self, flowKey, body, src, dst, tcp, responseCode):
        self.flowDict[flowKey] = {'body': body, 'type': 'chunked'}
        self.doStart(flowKey, body, src, dst, tcp, responseCode, 'chunked')
        contentLength = self.arbitraryChunkedLength
        progress = float(len(body)) / float(contentLength)
        packetContentLength = progress
        searchResults = self.bodySearch(body, contentLength)
        self.sendInfoAboutThisPacket(body, progress, packetContentLength, searchResults)  
        
    def parseExistingResponse(self, flowKey, body, src, dst, tcp):
        if self.flowDict[flowKey]['type'] == 'fixedLength':
            contentLength = self.flowDict[flowKey]['length']
            progress, packetContentLength = self.accumulateBodyAndReturnPacketPosition(flowKey, body, contentLength)
            mappedSearchResults = self.bodySearch(body, contentLength)
            self.sendInfoAboutThisPacket(body, progress, packetContentLength, mappedSearchResults)
            self.detectFixedLengthEnd(flowKey, src, dst)
        elif self.flowDict[flowKey]['type'] == 'chunked':
            contentLength = self.arbitraryChunkedLength
            progress, packetContentLength = self.accumulateBodyAndReturnPacketPosition(flowKey, body, contentLength)
            mappedSearchResults = self.bodySearch(body, contentLength)
            self.sendInfoAboutThisPacket(body, progress, packetContentLength, mappedSearchResults)
            self.detectChunkedEnd(body, src, dst)

    def accumulateBodyAndReturnPacketPosition(self, flowKey, body, contentLength):
        existingBody = self.flowDict[flowKey]['body']       
        newBody = self.flowDict[flowKey]['body'] = existingBody + body
        progress = float(len(newBody)) / float(contentLength)
        packetContentLength = float(len(body)) / float(contentLength)
        print str(len(newBody)) + '/' + str(contentLength)
        return progress, packetContentLength
   
    def sendInfoAboutThisPacket(self, body, progress, packetContentLength, mappedSearchResults):
        # call or response - relevant?
        self.oscSender('/progress', [progress])
        # if mappedSearchResults: # if list is not empty
        # self.oscSender('/searchResults', mappedSearchResults)   
        # self.oscSender('/bodyLength', [packetContentLength])   
        # self.oscSender('/body', [body])

    def detectFixedLengthEnd(self, flowKey, src, dst):
        accumulatedBodyLength = len(self.flowDict[flowKey]['body'])
        contentLength = self.flowDict[flowKey]['length']
        if accumulatedBodyLength > contentLength * 0.95: # temp fix for last packet not being received
            self.doStop(src, dst)

    def detectChunkedEnd(self, body, src, dst):
        if '0\r\n\r\n' in body: # doesn't always work
            self.doStop(src, dst)

    def doStart(self, flowKey, body, src, dst, tcp, responseCode, encodingType):
        host = self.hostDict[(src, dst)]['host']
        path = self.hostDict[(src, dst)]['path']
        destinationIP = dst[0]
        sourceIP = src[0]
        destinationPort = dst[1]
        scaledDestinationPort = self.scale(destinationPort, 49152, 65535, 0, 1)
        # no use to have the source Port as it will always be 80 (http)
        self.oscSender('/start', [responseCode, host, path[0:20], destinationIP, sourceIP, destinationPort, encodingType])

    def doStop(self, src, dst):
        host = self.hostDict[(src, dst)]['host']
        path = self.hostDict[(src, dst)]['path']
        del self.hostDict[(src, dst)] # need to do this?
        del self.flowDict[(src, dst)]
        self.oscSender('/stop', [host, path])

    def bodySearch(self, body, contentLength):
        searchResults = [m.start() for m in re.finditer(self.searchTerm, body)]
        mappedSearchResults = [float(item)/float(contentLength) for item in searchResults]
        return mappedSearchResults
        
    def oscSender(self, addr, params):
        msg = OSCMessage()
        msg.setAddress(addr)
        if params is not None:
            for param in params:
                msg.append(param)
        print "sending: " + str(msg) + " to: " + str(self.oscClient) # do not indent this line!
        try:
            self.oscClient.send(msg)
        except OSCClientError:
            # could explicitly try to detect errno 61 here
            print "WARNING: cannot send to SuperCollider"
            
    def scale(self, value, leftMin, leftMax, rightMin, rightMax):
        leftSpan = leftMax - leftMin
        rightSpan = rightMax - rightMin
        valueScaled = float(value - leftMin) / float(leftSpan)
        return rightMin + (valueScaled * rightSpan)

# methods

def main():
    
    dev = 'en1'
    
    # Open interface for catpuring.
    p = open_live(dev, 1500, 0, 100)

    # Set the BPF filter. See tcpdump(3).
    p.setfilter('tcp port 80') # only capture http packets

    print "Listening on %s: net=%s, mask=%s, linktype=%d" % (dev, p.getnet(), p.getmask(), p.datalink())

    # Start sniffing thread and finish main thread.
    DecoderThread(p).start()

    try : 
        while 1 : 
            time.sleep(1) 

    except KeyboardInterrupt :
        print "\nClosing OSCServer."
        server.close()
        print "Waiting for Server-thread to finish"
        # st.join() ##!!!
        print "Done"

main()
