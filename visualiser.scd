// simple GUI for peers and streams

(
~peerDict = List();

~makeMainGUI = {
	var rows;
	rows = [nil];
	~mainGUI = View(nil, Rect(0, 0, 200, 200)).front.alwaysOnTop_(true);
	~mainGUI.layout_(VLayout(*rows));
};

~addPeer = {arg sourceIP;
	var peerRow, streamRows, peerGUI;
	~peerDict.add(sourceIP);
	streamRows = [];
	peerGUI = [
		Button().states_([sourceIP]),
		View().layout_(VLayout(streamRows)).background_(Color.red)
	];
	peerRow = View().layout_(VLayout(*peerGUI));
	~mainGUI.layout.add(peerRow);
};

~rmvPeer = {arg sourceIP;
	var index;
	index = ~peerDict.indexOf(sourceIP);
	~mainGUI.layout.parent.children.removeAt(index).destroy; // remove
	~peerDict.remove(sourceIP);
};

~addStream = {arg sourceIP, sourcePort, destinationIP;
	// destination port is implied as port 80 i.e. http
	var peerIndex;
	peerIndex = ~peerDict.indexOf(sourceIP);
	~mainGUI.children[peerIndex].layout.add(
		View().layout_(HLayout([
			StaticText().string_(sourcePort),
			StaticText().string_(destinationIP)
		]));
	);
};

~removeStream = {arg sourceIP, sourcePort, destinationIP;
	// destination port is implied as port 80 i.e. http
};

~makeMainGUI.value;
)

~addPeer.value('192.168.1.3')
~addPeer.value('192.168.1.4')
~rmvPeer.value('192.168.1.3')
~rmvPeer.value('192.168.1.4')

~addStream.value('192.168.1.3', 54209, '10.0.0.1');
// only works with symbols for some reason

peer index

// incoming message = '/start', 0, 0)

~addPeerIfFirstTimeSeen = {arg peerIndex, sourceIP;

};


(
OSCFunc({arg msg;
	var sourceIndex, streamIndex, sourceIp, sourcePort, destIP;
	var source;
	# sourceIndex, streamIndex, sourceIp, sourcePort = msg.drop(1);
	msg.drop(1);
	// add source if first time seen:
	if (Source.all.keys.includes(peerIndex).not) {
		source = Source.new(peerIndex, sourceIP);
	};
	// add stream to source if first time source has seen this stream
	if (source.streams.keys.includes(sourceIndex).not) {
		source.addStream(streamIndex, sourcePort, destIP;
	};
}, '/start');

OSCFunc({arg msg;
	var sourceIndex, streamIndex;
	# sourceIndex, streamIndex = msg.drop(1);
}, '/stop');
)