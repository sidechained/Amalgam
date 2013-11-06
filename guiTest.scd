(
// p = "sudo python /Users/grahambooth/Desktop/Amalgam/github/packet-analyser.py".unixCmd;
// p.pidRunning

g !? { g.free }; g = TCPSourceStreamGUI();

(
OSCFunc({arg msg;
	var sourceIndex, streamIndex, callResponse;
	# sourceIndex, streamIndex, callResponse = msg.drop(1);
	msg.postln;
	if (callResponse == 0) { c = Color.red(alpha:0.2) } { c = Color.blue(alpha: 0.2) }
}, '/data');
)

DelayL.ar(