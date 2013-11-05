#!/usr/bin/python

# OSC API:

# /addSource [sourceIndex] [sourceIP]
# [remove source will never happen]
# /addStream [sourceIndex] [streamIndex] [sourcePort] [destIP]
# /removeStream [sourceIndex] [streamIndex]
# /startStream [sourceIndex] [streamIndex]
# /param [sourceIndex] [streamIndex] [param]
# /stopStream [sourceIndex] [streamIndex]

# addSource('128.9.9.1')
# removeSource('128.9.9.1')
# addStream('128.9.9.1', '1234')
# removeStream('128.9.9.1', '1234')
# // get source index
# sourceDict['128.9.9.1']['streamDict']['1234']['index']
# // get stream index
# sourceDict['128.9.9.1']['index']

#- when a TCP connection is added
#-- 1. check if (src) in source data structure
#--- if not, append to source data structure
#--- the index of this source in structure is the source index
#-- 2. check if (stream) is in source data structure at source index
#--- if not, append to it

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
        self.sourceDict = {}
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
        # Use the ImpactDecoder to turn the rawpacket into a hierarchy of ImpactPacket instances.
        eth = self.decoder.decode(data)        
        ip = eth.child()
        tcp = ip.child()
        src = (ip.get_ip_src(), tcp.get_th_sport() )
        dst = (ip.get_ip_dst(), tcp.get_th_dport() )
        # print tcp.get_packet()
        self.detectStart(tcp, src, dst)
        self.passFlow(tcp, src, dst) # flow should be passed before end
        self.detectEnd(tcp, src, dst)

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
                    self.startDetected(src, dst)

    def startDetected(self, src, dst):
        # source tracking
        sourceIP = src[0]
        streamKey = (src, dst)
        if sourceIP not in self.sourceDict:
            self.addSource(sourceIP)
        # stream tracking
        if streamKey not in self.sourceDict[sourceIP]['streamDict']:
            self.addStream(src, dst)
    
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
                    self.endDetected(src, dst)

    def endDetected(self, src, dst):
        sourceIP = src[0]
        if sourceIP in self.sourceDict: # only acknowledge termination if establishment has previously been acknowledged for this stream (prevent errors if start sniffing part way through a flow) - should really be done earlier in the code, why go through the whole handshake process before deciding?
            self.removeStream(src, dst) # never remove, causes stream to get mixed up, as when one stream ends it is removed and the index changes for all others (similar applies for peers, we don't know if a peer has really left or not)        

        # def detectHTTPRequest():
        # call only after connection establishment
        # looks for a packet:
        # -with a starting sequence number that matches the second message in the 3 way handshake
        # -with an ACK number that matches the ack of the 3rd message in the 3 way handshake
        # if found, parse the header and send relevant fields SuperCollider
        # sourceIP = src[0]
        # if sourceIP in self.sourceDict: # needed?
        # stream = (src,dst)
        # if stream in self.sourceDict[sourceIP]: # -from source to dest
        # if (tcp.get_PUSH() == 1) & (tcp.get_ACK() == 1): # -with PUSH and ACK flags set
        # None

        # def detectHTTPResponse():
        # None
 
    def passFlow(self, tcp, src, dst):
        # if the source or destination belong to an existing stream, forward data to that stream
        sourceIP = src[0]
        destinationIP = dst[0]
        if sourceIP in self.sourceDict:
            streamKey = (src, dst)
            if streamKey in self.sourceDict[sourceIP]['streamDict']:
                sourceIndex = self.sourceDict[sourceIP]['index']
                streamIndex = self.sourceDict[sourceIP]['streamDict'][streamKey]['index']
                cr = 0
                self.updateFlow(sourceIndex, streamIndex, tcp, src, dst, cr)
        elif destinationIP in self.sourceDict:
            reversedStreamKey = (dst, src)
            if reversedStreamKey in self.sourceDict[destinationIP]['streamDict']:
                sourceIndex = self.sourceDict[destinationIP]['index']
                streamIndex = self.sourceDict[destinationIP]['streamDict'][reversedStreamKey]['index']
                cr = 1
                self.updateFlow(sourceIndex, streamIndex, tcp, src, dst, cr)
                                
    def updateFlow(self, sourceIndex, streamIndex, tcp, src, dst, cr):
        #self.oscSender('/callResponse', [sourceIndex, streamIndex, cr])
        #self.oscSender('/sourceIP', [sourceIndex, streamIndex, src[0]])
        #self.oscSender('/sourcePort', [sourceIndex, streamIndex, src[1]])       
        #self.oscSender('/destIP', [sourceIndex, streamIndex, dst[0]])
        #self.oscSender('/destPort', [sourceIndex, streamIndex, dst[1]])
        #self.oscSender('/packetLength', [sourceIndex, streamIndex, tcp.parent().get_ip_len()])
        # self.oscSender('/setSeqNum', [sourceIndex, streamIndex, tcp.get_th_seq()])        
        # self.oscSender('/setAckNum', [sourceIndex, streamIndex, tcp.get_th_ack()])
        #self.oscSender('/data', [sourceIndex, streamIndex, tcp.get_bytes()])
        None
        
    def oscSender(self, name, params):
        msg = OSCMessage()
        msg.setAddress(name)
        for param in params:
            msg.append(param)
        self.oscClient.send(msg)
        print "sending: " + str(msg) + " to: " + str(self.oscClient)

    # source and stream management
    
    def addSource(self, sourceIP):
        # getting length with never work
        index = len(self.sourceDict)
        streamStack = range(100, -1, -1)
        self.sourceDict[sourceIP] = { 'index': index, 'streamDict': {}, 'streamStack': streamStack }
        sourceIndex = self.sourceDict[sourceIP]['index']
        self.oscSender('/addSource', [sourceIndex, sourceIP]) # send src port and dst ip here, for visualisation

    def removeSource(self, sourceIP):
        del self.sourceDict[sourceIP]

    def addStream(self, src, dst):
        sourceIP = src[0]
        streamKey = (src, dst)
        streamDict = self.sourceDict[sourceIP]['streamDict']
        index = self.sourceDict[sourceIP]['streamStack'].pop()
        streamDict[streamKey] = {'index': index }
        sourceIndex = self.sourceDict[sourceIP]['index']
        streamIndex = self.sourceDict[sourceIP]['streamDict'][streamKey]['index']
        # Q: should these be sent as separate messages?
        self.oscSender('/addStream', [sourceIndex, streamIndex, src[1], dst[0]]) # send src port and dst ip here, for visualisation

    def removeStream(self, src, dst):
        sourceIP = src[0]
        streamKey = (src, dst)        
        index = self.sourceDict[sourceIP]['streamDict'][streamKey]['index']
        self.sourceDict[sourceIP]['streamStack'].append(index) # push
        streamDict = self.sourceDict[sourceIP]['streamDict']
        sourceIndex = self.sourceDict[sourceIP]['index']
        streamIndex = self.sourceDict[sourceIP]['streamDict'][streamKey]['index']
        self.oscSender('/removeStream', [sourceIndex, streamIndex])
       
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

def main():

    dev = 'en1'

    # Open interface for catpuring.
    p = open_live(dev, 1500, 0, 100)

    # Set the BPF filter. See tcpdump(3).
    p.setfilter('tcp port 80') # only capture http packets

    print "Listening on %s: net=%s, mask=%s, linktype=%d" % (dev, p.getnet(), p.getmask(), p.datalink())

    # Start sniffing thread and finish main thread.
    DecoderThread(p).start()

main()
