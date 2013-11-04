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



