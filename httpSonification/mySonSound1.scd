s.boot

(
Ndef(\ggg, {arg r1, r2, r3, r4, env, response, releaseTime;
	// four freqs
	var a, b, verbed, out;
	a = LPF.ar(
		VarSaw.ar(
			r1+r2+r3+r4 / 0.2,
			iphase: [r4, r3, r2, r1] / 255 * 2 - 1,
			width: SinOsc.kr([r1, r2, r3, r4] / 255 * 2.2)),
		freq: r1+r2;
	);
	b = BPF.ar(
		SinOsc.ar(
			r1+r2+r3+r4 / 1.45,
			phase: SinOsc.kr([r1, r2, r3, r4])
		),
		freq: r1+r2 * SinOsc.kr([r1, r2, r3, r4] / 0.3).range(0.4, 1.7),
		rq: 0.2,
		mul: 0.015
	);
	out = SelectX.ar(response.lag(0.1), [a, b]);
	out = out * EnvGen.ar(Env.perc(0.01, releaseTime), response);
	verbed = GVerb.ar(out, roomsize: 17, revtime: 1.3) * 0.1;
	out = SelectX.ar(response.lag(0.1), [out, verbed] );
	out = out * env.lag(0.2) * 1;
	out = Pan2.ar(out, response * 2 - 1);
}).play
)

(
Ndef(\ggg, {arg r1, r2, r3, r4, env, response, releaseTime;
	// four freqs
	var a, b, verbed, deld, out;
	a =	SinOsc.ar(r1+r2+r3+r4);
	b = SinOsc.ar(r1+r2-r3-r4);
	out = SelectX.ar(response.lag(0.05), [a, b]);
	verbed = GVerb.ar(out, roomsize: 17, revtime: 1.3) * 0.1;
	deld = DelayC.ar(out, 0.2, SinOsc.kr([r1, r2, r3, r4]).range(0.05, 0.06));
	verbed = verbed * EnvGen.ar(Env.perc(0.01, 0.1, -16), response);
	deld = deld * EnvGen.ar(Env.perc(0.01, 0.2, -5), response);
	out = SelectX.ar(response.lag(0.05), [verbed, deld] );
	out = out * env.lag(0.2) * 0.3;
	out = Pan2.ar(out, response * 2 - 1);
}).play
)

(
OSCFunc({arg msg;
	var env;
	//msg.postln;
	env = msg.drop(3).first;
	Ndef(\ggg).set(\env, env);
}, '/env');

OSCFunc({arg msg;
	var sourceIP;
	//msg.postln;
	sourceIP = msg.drop(3).first;
	sourceIP = sourceIP.asString.split($.).collect{arg item; item.asInteger};
	Ndef(\ggg).set(\r1, sourceIP[0], \r2, sourceIP[1], \r3, sourceIP[2], \r4, sourceIP[3]);
}, '/sourceIP');

OSCFunc({arg msg;
	var destIP;
	//msg.postln;
	destIP = msg.drop(3).first;
	destIP = destIP.asString.split($.).collect{arg item; item.asInteger};
	destIP = destIP.linexp(0.0, 255.0, 100, 1000);
}, '/destIP');

OSCFunc({arg msg;
	var response;
	//msg.postln;
	response = msg.drop(3).first;
	Ndef(\ggg).set(\response, response);
}, '/response');

OSCFunc({arg msg;
	var packetLength;
	//msg.postln;
	packetLength = msg.drop(3).first;
	Ndef(\ggg).set(\releaseTime, packetLength.linlin(40, 1440, 0, 1));
}, '/packetLength');
)