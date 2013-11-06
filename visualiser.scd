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

