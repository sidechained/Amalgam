#!/usr/bin/python

# TODO:
# fix ends (packet length doesn't add up, chunked end packet not always received)
# find out why sometimes the body seems to be encryted
# body search trigger (parse as you go) - pass in searchTerm
# autodiscover peers (broadcast wifi address)

# TOFIX:
# messages continue to be sent even after stop

import sys
import string
import socket
import time
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
        self.searchTerm = 'option'
        self.ipDict = {
            '143.117.190.175': 'aidan',
            '143.117.178.248': 'michael',
            '143.117.177.118': 'graham',
            '143.117.185.92': 'robin'
            }
        self.hostDict = {}
        self.flowDict = {}
        # OSC functionality (mutlicasting for now)
        sendAddress1 = '127.0.0.1', 57120
        self.oscClient1=OSCClient()
        self.oscClient1.connect(sendAddress1)
        # initialise supercollider
        self.oscSender('/init', [1])
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
        # print tcp.get_packet()
        self.detectHTTP(tcp, src, dst)

    def detectHTTP(self, tcp, src, dst):
        packetString = tcp.get_data_as_string()

        # requests
        srcIp = src[0]
        if srcIp in self.ipDict: # only pass on data from players we know
            myName = self.ipDict[srcIp]
            request = HTTPRequest(packetString)
            if request.error_code is None:
                if request.command == 'GET':
                    if request.request_version == 'HTTP/1.1':
                        # store the host and path related to this request by unique key for later lookup:
                        self.hostDict[(dst, src)] = {}
                        self.hostDict[(dst, src)]['host'] = request.headers['host'] 
                        self.hostDict[(dst, src)]['path'] = request.path                        

        # responses
        dstIp = dst[0]
        if dstIp in self.ipDict: # only pass on data from players we know
            if (src, dst) in self.hostDict: # only pass on responses that relate to requests we've already logged
                myName = self.ipDict[dstIp]
                # parse HTTP/1.1 200 OK responses
                if packetString[:8] == "HTTP/1.1":
                    responseCode = packetString[9:12]
                    if responseCode == '200': # just okay responses for now
                        socket = FakeSocket(packetString)
                        response = HTTPResponse(socket)
                        response.begin()
                        headerArray = response.getheaders()
                        if '\r\n\r\n' in packetString:
                            bodyIndex = packetString.index('\r\n\r\n') + 4
                            body = packetString[bodyIndex:]
                            flowKey = (src, dst)
                            for item in headerArray:
                                if item[0] == 'content-type' and item[1] == 'text/html':
                                    for item in headerArray:
                                        if item[0] == 'content-length':
                                            print 'fixed length'
                                            self.flowDict[flowKey] = {'body': body, 'type': 'fixedLength', 'length': item[1]}
                                            self.doStart(myName, flowKey, body, src, dst, tcp)
                                        elif item[0] == 'transfer-encoding' and item[1] == 'chunked':
                                            print 'chunked'
                                            self.flowDict[flowKey] = {'body': body, 'type': 'chunked'}
                                            self.doStart(myName, flowKey, body, src, dst, tcp)
                        else:
                            print "body not found"

                # pass on
                existingFlowKey = (src, dst)
                if existingFlowKey in self.flowDict:               
                    body = packetString
                    if self.flowDict[existingFlowKey]['type'] == 'fixedLength':
                        self.doPerPacket(myName, existingFlowKey, body, src, tcp)
                        self.detectFixedLengthEnd(existingFlowKey, myName, src, dst)
                    elif self.flowDict[existingFlowKey]['type'] == 'chunked':
                        self.doPerPacket(myName, existingFlowKey, body, src, tcp)
                        self.detectChunkedEnd(body, myName, src, dst)

    def doStart(self, myName, flowKey, body, src, dst, tcp):
        host = self.hostDict[(src, dst)]['host']
        path = self.hostDict[(src, dst)]['path']
        self.oscSender('/start', [myName, host, path])
        #self.doPerPacket(myName, flowKey, body, src, tcp)

    def doStop(self, myName, src, dst):
        host = self.hostDict[(src, dst)]['host']
        path = self.hostDict[(src, dst)]['path']
        del self.hostDict[(src, dst)]
        self.oscSender('/stop', [myName, host, path])

    def doPerPacket(self, myName, flowKey, body, src, tcp):
        self.accumulateBody(myName, flowKey, body)
        self.bodySearch(myName, body)
        self.oscSender('/sourceIP', [myName, src[0]])
        self.oscSender('/sourcePort', [src[1]])
        self.oscSender('/packetLength', [tcp.parent().get_ip_len()])
        self.oscSender('/data', [myName, body])                                   

    def accumulateBody(self, myName, flowKey, body):
        accumulatedBody = self.flowDict[flowKey]['body']
        startIndex = len(accumulatedBody) + 1
        self.flowDict[flowKey]['body'] = accumulatedBody + body
        newAccumulatedBody = self.flowDict[flowKey]['body']
        stopIndex = len(newAccumulatedBody)
        self.oscSender('/packetByteRange', [myName, startIndex, stopIndex])   
                
    def bodySearch(self, myName, body):
        searchResults = body.find(self.searchTerm)
        if searchResults is not -1:
            self.oscSender('/bodyTrigger', [myName, searchResults]) # could use amount of times found here (or locations, actually)
        
    def oscSender(self, name, params):
        msg = OSCMessage()
        msg.setAddress(name)
        if params is not None:
            for param in params:
                msg.append(param)
        print "sending: " + str(msg) + " to: " + str(self.oscClient1)
        try:
            self.oscClient1.send(msg)
        except OSCClientError:
            # could explicitly try to detect errno 61 here
            print "ERROR: cannot send to SuperCollider"

    def detectFixedLengthEnd(self, flowKey, myName, src, dst):
        # targetLength = self.flowDict[existingFlowKey]['ength']
        # actualLength = len(self.flowDict[existingFlowKey]['body'])
        # print str(actualLength) + '/' + str(targetLength)
        # print float(actualLength)/float(targetLength)
        # actualLength is 832 bytes too long
        accumulatedBody = self.flowDict[flowKey]['body']
        contentLength = self.flowDict[flowKey]['length']
        if len(accumulatedBody) > contentLength:
            del self.flowDict[flowKey]
            self.doStop(myName, src, dst)

    def detectChunkedEnd(self, body, myName, src, dst):
        if '0\r\n\r\n' in body: # doesn't always work
            self.doStop(myName, src, dst)

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
