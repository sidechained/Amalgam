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
        handshakes = {}
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
        p = self.decoder.decode(data)
        ip = p.child()
        tcp = ip.child()
       
        return (p,ip,tcp,src,dst)
            
    def packetHandler(self, hdr, data):
        # Use the ImpactDecoder to turn the rawpacket into a hierarchy
        # of ImpactPacket instances.
        # Display the packet in human-readable form.
        eth = self.decoder.decode(data)        
        ip = eth.child()
        # TODO: restrict to TCP only port 80 (this would be better done at the pcap level)
        # Setting r"ip proto \tcp" as part of the pcap filter expression
        # suffices, and there shouldn't be any problem combining that with
        # other expressions.
        if isinstance(ip.child(), impacket.ImpactPacket.TCP):
            tcp = ip.child()
            src = (ip.get_ip_src(), tcp.get_th_sport() )
            dst = (ip.get_ip_dst(), tcp.get_th_dport() )
            self.detectStart(tcp, src, dst)

    def detectStart(thread, tcp, src, dst): # when passed, tcp grows into two arguments the first of which is a thread, why?!
        # stolen from: https://github.com/larrytheliquid/buffer-overflows/blob/master/project-2/project-2-submission/main.py
        # Handshake 1
        if tcp.get_th_flags() == TH_SYN:
            client_server = (src,dst)
            self.handshakes[client_server] = { "client_seq" : tcp.get_th_seq() }
        # Handshake 2
        elif tcp.get_th_flags() == TH_SYN | TH_ACK:
            client_server = (dst,src)
            if client_server in self.handshakes:
                hs = self.handshakes[client_server]
                if hs.get("client_seq",None) == tcp.get_th_ack() - 1:
                    hs["server_seq"] = tcp.get_th_seq()
        # Handshake 3
        elif tcp.get_th_flags() == TH_ACK:
            client_server = (src,dst)
            if client_server in self.handshakes:
                hs = self.handshakes[client_server]
                if hs.get("client_seq",None) == tcp.get_th_seq() - 1 and \
                   hs.get("server_seq",None) == tcp.get_th_ack() - 1:
                    self.handshakes.pop(client_server)
                    sendStart(src, dst)

    def sendStart(src, dst):
        print "succesful handshake"
        print (src, dst)

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

def main(filter):

    dev = 'en1'

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
