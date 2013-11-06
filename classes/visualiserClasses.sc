TCPSourceStreamGUI {

	var pythonAddr, <mainView, packetColor;
	var initOSCFunc, addSourceOSCFunc, addStreamOSCFunc, removeStreamOSCFunc, packetLengthOSCFunc, responseOSCFunc;

	*new {
		^super.new.init;
	}

	init {
		this.initOSCFuncs;
	}


	remoteInit {
		var sourceRows;
		sourceRows = [nil];
		pythonAddr = NetAddr("localhost", 8489);
		mainView = View(nil, Rect(Window.screenBounds.width, Window.screenBounds.height, 800, 200)).front.alwaysOnTop_(true);
		mainView.layout_(VLayout(*sourceRows).margins_(0).spacing_(0));
	}

	addSourceRow {arg sourceIndex, sourceIP;
		var sourceRow, streamRows, sourceLabel, sourceFilterButton, filterView, streamView;
		streamRows = [];
		sourceLabel = StaticText().string_(sourceIP);
		sourceFilterButton = Button().states_([
			["None", Color.black, Color.red(alpha:0.2)],
			["One", Color.black, Color.green(alpha:0.2)],
			["All", Color.black, Color.blue(alpha:0.2)]
		])
		.action_({arg butt; this.sendValueToPythonScript(sourceIP, butt.value)})
		.doAction;
		filterView = View().layout_(HLayout(*[sourceLabel, sourceFilterButton]));
		streamView = View().layout_(VLayout(streamRows)).background_(Color.red(alpha: 0.1));
		sourceRow = View().layout_(VLayout(*[filterView,streamView]).spacing_(2).margins_(0)).background_(Color.white);
		mainView.layout.insert(sourceRow, sourceIndex);
	}

	removeSourceRow {arg sourceIndex;
		mainView.layout.parent.children.removeAt(sourceIndex).destroy;
	}

	addStreamRow {arg sourceIndex, streamIndex, sourcePort, destinationIP;
		// destination port is implied as port 80 i.e. http
		var streamView, streamRow;
		streamView = View().layout_(HLayout(*[nil]).spacing_(1).margins_(0)).background_(Color.white);
		streamRow = View().layout_(HLayout(*[
			StaticText().string_(sourcePort).fixedWidth_(100),
			StaticText().string_(destinationIP).fixedWidth_(100),
			streamView
		]).margins_(0).spacing_(0));
		mainView.children[sourceIndex].children[1].layout.insert(streamRow, streamIndex);
	}

	removeStreamRow {arg sourceIndex, streamIndex;
		// destination port is implied as port 80 i.e. http
		mainView.children[sourceIndex].children[1].layout.parent.children.removeAt(streamIndex).destroy;
	}

	addPacket {arg sourceIndex, streamIndex, packetLength;
		var streamView;
		streamView = mainView.children[sourceIndex].children[1].layout.parent.children[streamIndex].layout.parent.children[2];
		streamView.layout.add(
			View().fixedWidth_(packetLength/500).background_(packetColor)
		)
	}

	setPacketColor {arg response;
		if (response == 1) {
			\red.postln;
			packetColor = Color.red(alpha:0.2)

		} {
			\blue.postln;
			packetColor = Color.blue(alpha: 0.2)
		}
	}

	sendValueToPythonScript {arg sourceIP, buttonValue;
		var filterType, msgToSend;
		filterType = case
		{ buttonValue == 0 } { filterType = '\none' }
		{ buttonValue == 1 } { filterType = '\one' }
		{ buttonValue == 2 } { filterType = '\all' };
		msgToSend = ['/setFilter', sourceIP, filterType];
		msgToSend.postln;
		pythonAddr.sendMsg(*msgToSend);
	}

	initOSCFuncs {

		initOSCFunc = OSCFunc({arg msg;
			var sourceIndex, sourceIP;
			# sourceIndex, sourceIP = msg.drop(1);
			msg.postln;
			defer {
				this.remoteInit;
			}
		}, '/init');

		// perhaps these should only be inited after the above /init is received?

		addSourceOSCFunc = OSCFunc({arg msg;
			var sourceIndex, sourceIP;
			# sourceIndex, sourceIP = msg.drop(1);
			msg.postln;
			defer {
				this.addSourceRow(sourceIndex, sourceIP);
			}
		}, '/addSource');

		addStreamOSCFunc = OSCFunc({arg msg;
			var sourceIndex, streamIndex, sourcePort, destinationIP;
			# sourceIndex, streamIndex, sourcePort, destinationIP = msg.drop(1);
			msg.postln;
			defer {
				this.addStreamRow(sourceIndex, streamIndex, sourcePort, destinationIP);
			}
		}, '/addStream');

		removeStreamOSCFunc = OSCFunc({arg msg;
			var sourceIndex, streamIndex;
			# sourceIndex, streamIndex = msg.drop(1);
			msg.postln;
			defer {
				this.removeStreamRow(sourceIndex, streamIndex);
			}
		}, '/removeStream');

		packetLengthOSCFunc = OSCFunc({arg msg;
			var sourceIndex, streamIndex, packetLength;
			# sourceIndex, streamIndex, packetLength = msg.drop(1);
			msg.postln;
			defer {
				this.addPacket(sourceIndex, streamIndex, packetLength);
			}
		}, '/packetLength');

		responseOSCFunc = OSCFunc({arg msg;
			var sourceIndex, streamIndex, response;
			# sourceIndex, streamIndex, response = msg.drop(1);
			msg.postln;
			this.setPacketColor(response)
		}, '/response');

	}

	free {
		mainView.destroy;
		initOSCFunc.free;
		addSourceOSCFunc.free;
		addStreamOSCFunc.free;
		removeStreamOSCFunc.free;
		packetLengthOSCFunc.free;
		responseOSCFunc.free;
	}

}