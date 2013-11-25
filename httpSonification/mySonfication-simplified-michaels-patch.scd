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

(
Ndef(\determExpPulses,{ arg
	trigFreq=100,
	attT=0,
	decT=0.5,
	f1=1000,
	f2=2000,
	f3=3000,
	f4=4000,
	rq=0.01,
	decTC=0.2,
	delT=0.05,
	delTRate=0.50,
	amp=0.5,
	level=1,
	gain=0.1,
	morphFactor=1;
	var trig,noise,fof,signal, freq;
	freq = [f1, f2, f3, f4];
	trig = LocalIn.ar(1);
	trig = Impulse.ar(trigFreq);
	LocalOut.ar(trig);
	noise = Resonz.ar(Decay2.ar(trig,attT,decT,WhiteNoise.ar(amp)),freq,rq)*rq.reciprocal;
	fof = Formlet.ar(trig,freq,attT,decT,amp);
	signal = LinXFade2.ar(noise,fof,morphFactor);
	signal = CombC.ar(signal,1,delT,decTC);
	signal = signal*level;
	signal = signal*gain;
	signal = Pan2.ar(signal, morphFactor * 2 - 1);
}).play
)

Ndef(\determExpPulses).gui(15)

Ndef(\determExpPulses).clear

OSCFunc.trace

(
// API
OSCFunc({arg msg;
	var env;
	//msg.postln;
	env = msg.drop(3).first;
	Ndef(\determExpPulses).set(\amp, env);
}, '/env');

OSCFunc({arg msg;
	var sourceIP;
	//msg.postln;
	sourceIP = msg.drop(3).first;
	sourceIP = sourceIP.asString.split($.).collect{arg item; item.asInteger};
}, '/sourceIP');

OSCFunc({arg msg;
	var destinationIP;
	//msg.postln;
	destinationIP = msg.drop(3).first;
	destinationIP = destinationIP.asString.split($.).collect{arg item; item.asInteger};
	destinationIP.postln;
	Ndef(\determExpPulses).set(\f1, destinationIP[0], \f2, destinationIP[1], \f3, destinationIP[2], \f4, destinationIP[3]);
}, '/destinationIP');

OSCFunc({arg msg;
	var response;
	//msg.postln;
	response = msg.drop(3).first;
	Ndef(\determExpPulses).set(\morphFactor, response * 2 - 1);
}, '/response');

OSCFunc({arg msg;
	var packetLength;
	//msg.postln;
	packetLength = msg.drop(3).first;
}, '/packetLength');
)

// call and response control Xfade between two very different sounds
// call and response should be able to overlap (two separate defs)
// each packet should be a synth