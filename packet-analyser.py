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
        self.flowDict = []
        self.handshakes = {}
        self.endshakes = {}
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
            self.detectEnd(tcp, src, dst)
            self.passFlow(tcp, src, dst)

    def detectStart(self, tcp, src, dst):
        # modified from: https://github.com/larrytheliquid/buffer-overflows/blob/master/project-2/project-2-submission/main.py

        # 02:29:04.696934 IP (tos 0x0, ttl 64, id 50453, offset 0, flags [DF], proto TCP (6), length 64)
        # 10.0.0.69.63660 > 64.4.11.42.80: Flags [S], cksum 0x3e5a (correct), seq 1634890365, win 65535
        # 02:29:04.875864 IP (tos 0x0, ttl 242, id 17512, offset 0, flags [DF], proto TCP (6), length 52)
        # 64.4.11.42.80 > 10.0.0.69.63660: Flags [S.], cksum 0x7468 (correct), seq 1876445385, ack 1634890366, win 8190
        # 02:29:04.876027 IP (tos 0x0, ttl 64, id 49239, offset 0, flags [DF], proto TCP (6), length 40)
        # 10.0.0.69.63660 > 64.4.11.42.80: Flags [.], cksum 0x94d1 (correct), seq 1634890366, ack 1876445386, win 16384, length 0
        # 02:29:04.876151 IP (tos 0x0, ttl 64, id 16719, offset 0, flags [DF], proto TCP (6), length 158)
        
        # SYN: The active open is performed by the client sending a SYN to the server.
        # The client sets the segment's sequence number to a random value A.
        # SYN-ACK: In response, the server replies with a SYN-ACK.
        # The acknowledgment number is set to one more than the received sequence number i.e. A+1
        # ...and the sequence number that the server chooses for the packet is another random number, B.
        # ACK: Finally, the client sends an ACK back to the server.
        # The sequence number is set to the received acknowledgement value i.e. A+1,
        # and the acknowledgement number is set to one more than the received sequence number i.e. B+1.

        # Csam replies with a similar packet except it includes a piggy-backed ack for rtsg's SYN. Rtsg then acks csam's SYN. The `.' means the ACK flag was set. The packet contained no data so there is no data sequence number. Note that the ack sequence number is a small integer (1). The first time tcpdump sees a tcp `conversation', it prints the sequence number from the packet. On subsequent packets of the conversation, the difference between the current packet's sequence number and this initial sequence number is printed. This means that sequence numbers after the first can be interpreted as relative byte positions in the conversation's data stream (with the first data byte each direction being `1'). `-S' will override this feature, causing the original sequence numbers to be output.        

        if (tcp.get_SYN() == 1) & (tcp.get_ACK() == 0): # request: SYN without ACK
            cs = (src,dst)            
            if cs not in self.handshakes:
                self.handshakes[cs] = { "client_seq" : tcp.get_th_seq() }

        elif (tcp.get_SYN() == 1) & (tcp.get_ACK() == 1): # request: SYN with ACK        
            cs = (dst,src)
            if cs in self.handshakes:
                hs = self.handshakes[cs]
                if (hs.get("client_seq", None)) == (tcp.get_th_ack() - 1):
                    hs["server_seq"] = tcp.get_th_seq()                    
                    hs["server_ack"] = tcp.get_th_ack()

        if (tcp.get_SYN() == 0) & (tcp.get_ACK() == 1): # acknowledgement: ACK without SYN
            cs = (src,dst)
            if cs in self.handshakes:
                hs = self.handshakes[cs]
                if (hs["server_seq"] == tcp.get_th_ack() - 1) & (hs["server_ack"] == tcp.get_th_seq()):
                    hs = self.handshakes[cs]
                    self.handshakes.pop(cs)
                    self.sendStart(src, dst)
                    self.flowDict.append((src, dst))

    def detectEnd(self, tcp, src, dst):
        # 02:29:41.824045 IP (tos 0x0, ttl 64, id 62228, offset 0, flags [DF], proto TCP (6), length 40)
        # 10.0.0.69.63661 > 64.4.11.42.80: Flags [F.], cksum 0xfc20 (correct), seq 3708332116, ack 2779445817, win 16384, length 0
        # 02:29:42.002991 IP (tos 0x0, ttl 242, id 43373, offset 0, flags [DF], proto TCP (6), length 40)
        # 64.4.11.42.80 > 10.0.0.69.63661: Flags [F.], cksum 0x3a21 (correct), seq 2779445817, ack 3708332117, win 511, length 0
        # 02:29:42.003103 IP (tos 0x0, ttl 64, id 63350, offset 0, flags [DF], proto TCP (6), length 40)
        # 10.0.0.69.63661 > 64.4.11.42.80: Flags [.], cksum 0xfc1f (correct), seq 3708332117, ack 2779445818, win 16384, length 0        
        
        if (tcp.get_FIN() == 1) & (tcp.get_ACK() == 1):
            cs = (src,dst)
            if cs not in self.endshakes: # request
                self.endshakes[cs] = { "client_seq" : tcp.get_th_seq(), "client_ack" : tcp.get_th_ack() }
                
        if (tcp.get_FIN() == 1) & (tcp.get_ACK() == 1):
            cs = (dst,src)           
            if cs in self.endshakes: # respond
                es = self.endshakes[cs]
                if es.get("client_seq",None) == tcp.get_th_ack() - 1 and \
                  es.get("client_ack",None) == tcp.get_th_seq():
                    es["server_seq"] = tcp.get_th_seq()
                    es["server_ack"] = tcp.get_th_ack()

        if (tcp.get_FIN() == 0) & (tcp.get_ACK() == 1):
            cs = (src,dst)
            if cs in self.endshakes: # acknowledge
                es = self.endshakes[cs]
                if es.get("server_seq",None) == tcp.get_th_ack() - 1 and \
                  es.get("server_ack",None) == tcp.get_th_seq():
                    self.endshakes.pop(cs)
                    self.sendEnd(src, dst)
                    self.flowDict.remove((src, dst)) # only removes first instance

    def sendStart(self, src, dst):
        print "connection established between:" + str((src, dst))
        key = str(src[0]) + '.' + str(src[1]) + '-' + str(dst[0]) + '.' + str(dst[1])
        msg = OSCMessage()
        msg.setAddress('/start')
        msg.append(key)
        self.oscClient.send(msg)

    def sendEnd(self, src, dst):
        print "connection terminated between:" + str((src, dst))
        key = str(src[0]) + '.' + str(src[1]) + '-' + str(dst[0]) + '.' + str(dst[1])
        msg = OSCMessage()
        msg.setAddress('/stop')
        msg.append(key)
        self.oscClient.send(msg)

    def passFlow(self, tcp, src, dst):
        if (src, dst) in self.flowDict:
            key = str(src[0]) + '.' + str(src[1]) + '-' + str(dst[0]) + '.' + str(dst[1])
            cr = 0
            self.updateFlow(key, tcp, src, dst, cr)
        if (dst, src) in self.flowDict:
            key = str(dst[0]) + '.' + str(dst[1]) + '-' + str(src[0]) + '.' + str(src[1])
            cr = 1
            self.updateFlow(key, tcp, src, dst, cr)
            
    def updateFlow(self, key, tcp, src, dst, cr):
        self.oscSender('/callResponse', key, cr)
        self.oscSender('/setSourceIP', key, src[0])
        self.oscSender('/setSourcePort', key, src[1])       
        self.oscSender('/setDestIP', key, dst[0])
        self.oscSender('/setDestPort', key, dst[1])
        self.oscSender('/setSourceIP', key, tcp.parent().get_ip_len())
        # self.oscSender('/setSeqNum', key, tcp.get_th_seq())        
        # self.oscSender('/setAckNum', key, tcp.get_th_ack())
        self.oscSender('/setData', key, tcp.get_packet())

    def oscSender(self, name, key, parameter):
        msg = OSCMessage()
        msg.setAddress(name)
        msg.append(key)
        msg.append(parameter)
        self.oscClient.send(msg)
        print "sending: " + str(msg) + " to: " + str(self.oscClient)

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
