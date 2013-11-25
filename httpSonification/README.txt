* Amalgam Collective: Sonification Instructions

1. Download and install OSCseq (a nice freeware Open Sound Control recorder/player) from: http://oscseq.com/download/

2. Open OSCseq and load in one of the supplied test files. I have provided files for three websites, named:

OSCseq-wikileaks.xml (small)
OSCseq-amazon.xml (medium)
OSCseq-wikipediaUSA.xml (long)

3. Playback the file, which should be set up so as to continuously loop around the data. You should see that there are separate columns for each OSC tag.

4. Now set up a connection in OSCseq for the application you will be sending the OSC data to:

i.	In OSCseq, go to the File menu and choose OSC Connections
ii.	In the 'Add new' section, choose 'Manual' from the drop down list
iii.	Enter the IP as '127.0.0.1' and port as the port you will use in your receiving application (i.e. SuperCollider would be 57120)

5. Set up your chosen application (i.e. Max, SuperCollider, etc) to receive on '127.0.0.1' (localhost) using the port you chose in step 4. Application specific examples:

a) In SuperCollider:

First try…

OSCFunc.trace(true)

…to see if the data is being received.

If so, proceed to setting up OSCFunc's for each message type, e.g.

OSCFunc({arg msg;
	msg.postln; // print the whole message
	msg.drop(3).postln; // strip off the message name and first two ID's (not used for now)
}, '/response', recvPort: 57120)

b) In Max (for PD should be similar…):

i.	Set up a udpreceive object on your chosen port
ii.	Connect the outlet of udpreceive to a print object, to check the messages are coming in
iii. 	use the OSC-Route external to separate the messages (see http://cnmat.berkeley.edu/patch/4029)
iv.	remember to strip off the first two numbers of each message (for now)

Finally, for more info on setting up OSCseq see: http://oscseq.com/manual/

* The OSC Scheme

For an overview, see the attached PDF, but here's a quick reminder:

- streams start with an /addStream message and end with /removeStream
- directly after an /addStream you should get an /env message, in the middle you should also get one, and another at the /end (before /removeStream)
- for each received packet, you'll get the following kind of info:

/sourceIP 0 0 64.4.11.42/destPort 0 0 49208/destIP 0 0 149.170.221.115/sourcePort 0 0 -3./response 0 0 1/sourceIP 0 0 149.170.221.115/destIP 0 0 64.4.11.42/sourcePort 0 0 0./destPort 0 0 80/response 0 0 0/packetLength 0 0 40

/packetLength and /response are probably the most useful ones for now. I'll have a think of how to use some of the other data (destIP could somehow be used to differentiate each connection). 

So…map this all as you see fit, but remember to strip off the two leading numbers for now (they refer to source index and stream index, so we can sonify multiple streams in the end, hopefully)

That's it for now, any questions or problems just drop me a line.

Cheers,
Graham