TCPSource {

	classvar <all;
	var gui, <index, <ip, <streams;

	*initClass {
		all = IdentityDictionary.new;
	}

	*new {arg gui, index, ip;
		^super.newCopyArgs(gui, index, ip).init;
	}

	init {
		streams = [];
		all.put(index, this);
		gui.postln;
		defer { gui.addSourceRow(this); };
	}

	addStream {arg streamIndex, sourcePort, destIP;
		var stream;
		stream = TCPStream(this, streamIndex, sourcePort, destIP);
		streams.put(streamIndex, stream);
	}

	removeStream {arg streamIndex;
		streams.removeAt(streamIndex);
	}

}

TCPStream {

	var source, streamIndex, sourcePort, destIP;
	// destport is implied (80)

	*new {arg source, streamIndex, sourcePort, destIP;
		^super.newCopyArgs(source, streamIndex, sourcePort, destIP).init;
	}

	init {

	}

}

TCPSourceStreamGUI {

	var gui;

	*new {
		^super.new.init;
	}

	init {
		var rows;
		rows = [nil];
		gui = View(nil, Rect(0, 0, 200, 200)).front.alwaysOnTop_(true);
		gui.layout_(VLayout(*rows));
	}

	addSourceRow {arg source;
		var sourceRow, streamRows, sourceGUI;
		streamRows = [];
		sourceGUI = [
			Button().states_([[source.ip]]),
			View().layout_(VLayout(streamRows)).background_(Color.red)
		];
		sourceRow = View().layout_(VLayout(*sourceGUI));
		gui.layout.add(sourceRow);
	}

	removeSourceRow {arg source;
		gui.layout.parent.children.removeAt(source.ip).destroy; // remove
	}

	addStreamRow {arg stream;
		// destination port is implied as port 80 i.e. http
		gui.children[stream.sourceIndex].layout.add(
			View().layout_(HLayout([
				StaticText().string_(stream.sourcePort),
				StaticText().string_(stream.destinationIP)
			]));
		);
	}

	removeStreamRow {arg stream;
		// destination port is implied as port 80 i.e. http
	}

}



