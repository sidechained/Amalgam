// single Ndef for now, which runs constantly
// start/stop will set it's volume

// OSC API:
//
// \start			key 	starts a synth
// \callResponse	key 	0/1
// \srcIP			key
// \dstIP			key
// \srcPort			key
// \synFlag			key
// \ackFlag			key		0/1
// \packetLength	key		0/1
// \http			key
// \data 			key
// \stop			key		stops a synth

OSCFunc.trace(false)
OSCFunc.trace(true)

(
~setupOSCFuncs = {

	OSCFunc({arg msg;
		// make a Synth, put it in the ~dict at key
		var peerIndex, streamIndex, synth;
		# peerIndex, streamIndex = msg.drop(1);
		// msg.postln;
		Ndef(\sonify).set(\amp, 1);
	}, '/start');

	OSCFunc({arg msg;
		// lookup a Synth, remove it from the ~dict at key
		var key, synth;
		# key = msg.drop(1);
		// msg.postln;
		Ndef(\sonify).set(\amp, 0);
	}, '/stop');

	OSCFunc({arg msg;
		// lookup a Synth, remove it from the ~dict at key
		var peerIndex, streamIndex, value, synth;
		# peerIndex, streamIndex, value = msg.drop(1);
		msg.postln;
		Ndef(\sonify).set(\callResponse, value);
	}, '/callResponse');

	OSCFunc({arg msg;
		// lookup a Synth, remove it from the ~dict at key
		var peerIndex, streamIndex, value, synth;
		# peerIndex, streamIndex, value = msg.drop(1);
		// msg.postln;
		Ndef(\sonify).set(\sourcePort, value);
	}, '/sourcePort');

};

~setupOSCFuncs.value;

fork {
	s.boot;
	s.bootSync;
};
)

(
Ndef(\sonify, {arg sourcePort, callResponse, amp = 0;
	var freq = 440;
	var pw = callResponse.range(0.25, 0.5);
	Pulse.ar(freq, width: pw) * amp;
}).play;
)
