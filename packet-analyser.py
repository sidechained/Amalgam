#!/usr/bin/python
# Copyright (c) 2003 CORE Security Technologies
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# $Id: sniff.py 17 2003-10-27 17:36:57Z jkohen $
#
# Simple packet sniffer.
#
# This packet sniffer uses the pcap library to listen for packets in
# transit over the specified interface. The returned packages can be
# filtered according to a BPF filter (see tcpdump(3) for further
# information on BPF filters).
#
# Note that the user might need special permissions to be able to use pcap.
#
# Authors:
#  Maximiliano Caceres <max@coresecurity.com>
#  Javier Kohen <jkohen@coresecurity.com>
#
# Reference for:
#  pcapy: findalldevs, open_live.
#  ImpactDecoder.

import sys
import string
from BaseHTTPServer import BaseHTTPRequestHandler
from httplib import HTTPResponse
from StringIO import StringIO
from threading import Thread
from OSC import OSCClient, OSCMessage

import pcapy
from pcapy import findalldevs, open_live
import impacket
from impacket.ImpactDecoder import EthDecoder, LinuxSLLDecoder

class DecoderThread(Thread):
    def __init__(self, pcapObj):
        # OSC functionality:
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
        # Use the ImpactDecoder to turn the rawpacket into a hierarchy
        # of ImpactPacket instances.
        # Display the packet in human-readable form.
        ethPacket = self.decoder.decode(data)        
        ipPacket = ethPacket.child()
        # TODO: restrict to TCP only port 80 (this would be better done at the pcap level)
        # Setting r"ip proto \tcp" as part of the pcap filter expression
        # suffices, and there shouldn't be any problem combining that with
        # other expressions.
        if isinstance(ipPacket.child(), impacket.ImpactPacket.TCP):
        # NOW: whichever direction the src and dst are first found in will = key
        # BUT: key should really always be formatted from local point of view, how to determine local
            tcpPacket = ipPacket.child()
            key = str(ipPacket.get_ip_src()) + '.' + str(tcpPacket.get_th_sport()) + '-' + str(ipPacket.get_ip_dst()) + '.' + str(tcpPacket.get_th_dport())
            msg = OSCMessage()
            msg.setAddress('/toSonify')
            msg.append(key)
            msg.append(":".join([str(x) for x in ethPacket.get_ether_shost()]))
            msg.append(ipPacket.get_ip_src())
            msg.append(tcpPacket.get_th_sport())
            msg.append(":".join([str(x) for x in ethPacket.get_ether_dhost()]))
            msg.append(ipPacket.get_ip_dst())
            msg.append(tcpPacket.get_th_dport())
            msg.append(ipPacket.get_ip_len())
            # msg.append(tcpPacket.get_th_seq())
            # msg.append(tcpPacket.get_th_ack())
            msg.append(tcpPacket.get_ACK())
            msg.append(tcpPacket.get_SYN())
            msg.append(tcpPacket.get_FIN())
            msg.append(tcpPacket.get_packet())
            self.oscClient.send(msg)
        
        # responses:
        # if isinstance(ipPacket.child(), impacket.ImpactPacket.TCP):
        #     tcpData = ipPacket.child().get_packet()
        #     socket = FakeSocket(tcpData)
        #     response = HTTPResponse(socket).begin()
        #     print response
        #     if response is not None:
        #         print response.getheaders()
        #         print response.msg
        #         print response.status

        # requests:        
        # request = HTTPRequest(tcpData)
            # if request.error_code is None:
                # print request.error_code       # None  (check this first)
                # print request.command          # "GET"
                # print request.path             # "/who/ken/trust.html"
                # print request.request_version  # "HTTP/1.1"
                # print len(request.headers)     # 3
                # print request.headers.keys()   # ['accept-charset', 'host', 'accept']
                # print request.headers['host']  # "cm.bell-labs.com" 

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

# methods
     
def getInterface():
    # Grab a list of interfaces that pcap is able to listen on.
    # The current user will be able to listen from all returned interfaces,
    # using open_live to open them.
    ifs = findalldevs()

    # No interfaces available, abort.
    if 0 == len(ifs):
        print "You don't have enough permissions to open any interface on this system."
        sys.exit(1)

    # Only one interface available, use it.
    elif 1 == len(ifs):
        print 'Only one interface present, defaulting to it.'
        return ifs[0]

    # Ask the user to choose an interface from the list.
    count = 0
    for iface in ifs:
        print '%i - %s' % (count, iface)
        count += 1
    idx = int(raw_input('Please select an interface: '))

    return ifs[idx]

def main(filter):

    dev = getInterface()

    # Open interface for catpuring.
    p = open_live(dev, 1500, 0, 100)

    # Set the BPF filter. See tcpdump(3).
    p.setfilter(filter)

    print "Listening on %s: net=%s, mask=%s, linktype=%d" % (dev, p.getnet(), p.getmask(), p.datalink())

    # Start sniffing thread and finish main thread.
    DecoderThread(p).start()

# Process command-line arguments. Take everything as a BPF filter to pass
# onto pcap. Default to the empty filter (match all).
filter = ''
if len(sys.argv) > 1:
    filter = ' '.join(sys.argv[1:])
    print filter

main(filter)
