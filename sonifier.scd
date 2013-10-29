// Networking Sonification Scheme

dict = IdentityDictionary.new();

// each entry in the dictionary represents a 'conversation' between a client and server, the unique name for which is a concatenation of name + i.e. '192.168.62.1.1000-168.0.0.1.2000'
// the dictionary itself will store a synth, which can then be looked up by the unique name

startResponder = OSCFunc({arg msg;
	// responder that will trigger the start of the sound and some initial parameters e.g.
	var id, senderIP, senderPort, receiverIP, receiverPort; // PLUS info from GET header
	var synth;
	# id, senderIP, senderPort, receiverIP, receiverPort = msg.drop(1);
	// map the data
	synth = Synth(\sonifier, [\arg, ]);
	dict.put(id, synth);
}, '/start');

// the HTTP response 'FOUND' or 'NOT FOUND' (or however?) will trigger a change in the sound
'/response'

OSCFunc.trace

// the HTTP request 'get' moves the sound

setResponder = OSCFunc({arg msg;
	// responder for low level packet info will be used to for timbral variation of the sound
	// how to turn payload into raw timbral data
	// sender and receiver will switch here depending on the direction of the conversation or 'flow'
	var id, senderIP, senderPort, receiverIP, receiverPort; // PLUS low level packet details + payload
	var synth;
	# id, senderIP, senderPort, receiverIP, receiverPort = msg.drop(1);
	synth = dict.at();
}, '/tcpPacket');

// a range of possible end HTTP responses (OK, NOT FOUND) will trigger the end of the sound