// what is hard about sonifying this data?
// - env doesn't really produce any kind of env (need to know progression throughout the file, then remap to an envelope)
// - it's not useful if sourceIP and destIP change, should be localIP and remoteIP and set once at the beginning of the transfer (call, response could then set the)
// - likewise there should only be localport

// strategies for creating interesting sound events:

// 1. the fingerprint of the
// 2.
// 3. use 'data' as
// 4. measure the

// use the http body itself

// ip ->

// /sourceIP 0 0 64.4.11.42
// /destPort 0 0 49208
// /destIP 0 0 149.170.221.115
// /sourcePort 0 0 -3.
// /response 0 0 1
// /sourceIP 0 0 149.170.221.115
// /destIP 0 0 64.4.11.42
// /sourcePort 0 0 0.
// /destPort 0 0 80
// /response 0 0 0
// /packetLength 0 0 40

// packet length never seems to vary - just jumps between 52 and 1420

s.boot

OSCFunc.trace

(
// API

OSCFunc({arg msg;
	var response;
	msg.postln;
	response = msg.drop(3).first;
	Ndef(\sonify).set(\amp, response);
}, '/response');
)

(
OSCFunc({arg msg;
	var sourceIP, freqs;
	msg.postln;
	sourceIP = msg.drop(3).first;
	sourceIP = sourceIP.asString.split($.).collect{arg item; item.asInteger};
	freqs = sourceIP.linexp(0, 255, 200, 600);
	Ndef(\sonify).set(\f0, freqs[0], \f1, freqs[1], \f2, freqs[2], \f3, freqs[3]);
}, '/sourceIP');

OSCFunc({arg msg;
	var response;
	msg.postln;
	response = msg.drop(3).first;
	Ndef(\sonify).set(\timbre, response);
}, '/response');

OSCFunc({arg msg;
	var env;
	msg.postln;
	env = msg.drop(3).first;
	Ndef(\sonify).set(\amp, env);
}, '/env');

OSCFunc({arg msg;
	var packetLength;
	msg.postln;
	packetLength = msg.drop(3).first;
	packetLength = packetLength.linlin(52.0, 1420.0, 0.0, 1.0);
	Ndef(\sonify).set(\timbre, packetLength);
}, '/packetLength');
)


(
Ndef(\sonify, {arg amp = 1, f0, f1, f2, f3, timbre;
	var sin, out;
	sin = VarSaw.ar([f0, f1, f2, f3], width: timbre.linlin(0, 1, 0.25, 0.75).lag(0.1), mul: [1, 0.75, 0.5, 0.25]);
	out = sin * amp.lag(0.01);
	out = out * 0.2;
	out = GVerb.ar(out, revtime: 0.2);
	out ! 2;
}).play
)

Ndef(\sonify).clear

// approach 2

(
Ndef(\sonify, {arg amp = 1, f0, f1, f2, f3, timbre;
	var sin, out;
	sin = VarSaw.ar([f0, f1, f2, f3], width: timbre.linlin(0, 1, 0.25, 0.75).lag(0.1), mul: [1, 0.75, 0.5, 0.25]);
	out = sin * amp.lag(0.01);
	out = out * 0.2;
	out = GVerb.ar(out, revtime: 0.2);
	out ! 2;
}).play
)
