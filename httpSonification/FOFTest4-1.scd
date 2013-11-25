s.boot; s.scope(2)

(
SynthDef(\expPulses,{ arg out=0,minTrigFreq=0.1,maxTrigFreq=10,minAttT=0.001,maxAttT=1,minDecT=0.001,maxDecT=1,minFreq=40,maxFreq=12000,rq=0.7,decTC=0.2,minDelT=0.01,maxDelT=0.15,minDelTRate=0.05,maxDelTRate=0.15,minAmp=0.5,maxAmp=1,level=1,morphFactor=1;
	var trig,noise,fof,amp,freq,attT,decT,signal;

	trig = LocalIn.ar(1);
	trig = Impulse.ar(TExpRand.ar(minTrigFreq,maxTrigFreq,trig));
	LocalOut.ar(trig);

	amp = TRand.ar(minAmp,maxAmp,trig);
	freq = TExpRand.ar(minFreq,maxFreq,trig);
	attT = TRand.ar(minAttT,maxAttT);
	decT = TRand.ar(minDecT,maxDecT);
	noise = Resonz.ar(Decay2.ar(trig,attT,decT,WhiteNoise.ar(amp)),freq,rq)*rq.reciprocal;
	fof = Formlet.ar(trig,freq,attT,decT,amp);
	signal = LinXFade2.ar(noise,fof,morphFactor);

	signal = CombC.ar(signal,1,{LFDNoise1.kr(LFDNoise1.kr(1).range(minDelTRate,maxDelTRate)).range(minDelT,maxDelT)}!5,decTC).sum;

	Out.ar(out,signal*level)
}).add;

SynthDef(\oneStageEnv,{ arg out,brPt1=0,brPt2=1,segT1=1,segC1=1;
	Out.kr(out,EnvGen.kr(Env([brPt1,brPt2],[segT1],segC1),doneAction:2))
}).add;

SynthDef(\twoStageEnv,{ arg out,brPt1=0,brPt2=1,brPt3=0,segT1=1,segT2=1,segC1=1,segC2=1;
	Out.kr(out,EnvGen.kr(Env([brPt1,brPt2,brPt3],[segT1,segT2],[segC1,segC2]),doneAction:2))
}).add;

SynthDef(\threeStageEnv,{ arg out,brPt1=0,brPt2=1,brPt3=1,brPt4=0,segT1=1,segT2=1,segT3=1,segC1=1,segC2=1,segC3=1;
	Out.kr(out,EnvGen.kr(Env([brPt1,brPt2,brPt3,brPt4],[segT1,segT2,segT3],[segC1,segC2,segC3]),doneAction:2))
}).add;

SynthDef(\fourStageEnv,{ arg out,brPt1=0,brPt2=1,brPt3=1,brPt4=0,brPt5=0,segT1=1,segT2=1,segT3=1,segT4=1,segC1=1,segC2=1,segC3=1,segC4=1;
	Out.kr(out,EnvGen.kr(Env([brPt1,brPt2,brPt3,brPt4,brPt5],[segT1,segT2,segT3,segT4],[segC1,segC2,segC3,segC4]),doneAction:2))
}).add;

SynthDef(\fiveStageEnv,{ arg out,brPt1=0,brPt2=1,brPt3=1,brPt4=1,brPt5=0,brPt6=0,segT1=1,segT2=1,segT3=1,segT4=1,segT5=1,segC1=1,segC2=1,segC3=1,segC4=1,segC5=1;
	Out.kr(out,EnvGen.kr(Env([brPt1,brPt2,brPt3,brPt4,brPt5,brPt6],[segT1,segT2,segT3,segT4,segT5],[segC1,segC2,segC3,segC4,segC5]),doneAction:2))
}).add
)

s.sendMsg('/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,100,\maxTrigFreq,100,\minAttT,0.0001,\maxAttT,0.0001,\minDecT,0.001,\maxDecT,0.001,\minFreq,400,\maxFreq,400,\minAmp,1,\maxAmp,1,\rq,0.1)

// SOUND EXAMPLES

// sustained bowed string like (pure FOF synthesis -> morphFactor=1)
(
s.sendBundle(nil,
	// left channel
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,203,\maxTrigFreq,203,\minAttT,0.001,\maxAttT,0.001,\minDecT,0.035,\maxDecT,0.035,\minAmp,1,\maxAmp,1,\minFreq,494,\maxFreq,494,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.011,\minDelTRate,0.05,\maxDelTRate,0.15,\decTC,2.67,\level,0.031,\out,0],
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,101.5,\maxTrigFreq,101.5,\minAttT,0.002,\maxAttT,0.002,\minDecT,0.035,\maxDecT,0.035,\minAmp,1,\maxAmp,1,\minFreq,307,\maxFreq,307,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.011,\minDelTRate,0.05,\maxDelTRate,0.15,\decTC,1.4,\level,0.056,\out,0],
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,406,\maxTrigFreq,406,\minAttT,0.001,\maxAttT,0.001,\minDecT,0.018,\maxDecT,0.18,\minAmp,1,\maxAmp,1,\minFreq,1280,\maxFreq,1280,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.011,\minDelTRate,0.05,\maxDelTRate,0.15,\decTC,4.72,\level,0.02,\out,0],
	// right channel
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,203,\maxTrigFreq,203,\minAttT,0.001,\maxAttT,0.001,\minDecT,0.035,\maxDecT,0.035,\minAmp,1,\maxAmp,1,\minFreq,494,\maxFreq,494,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.011,\minDelTRate,0.05,\maxDelTRate,0.15,\decTC,2.67,\level,0.031,\out,1],
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,101.5,\maxTrigFreq,101.5,\minAttT,0.002,\maxAttT,0.002,\minDecT,0.035,\maxDecT,0.035,\minAmp,1,\maxAmp,1,\minFreq,307,\maxFreq,307,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.011,\minDelTRate,0.05,\maxDelTRate,0.15,\decTC,1.4,\level,0.056,\out,1],
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,406,\maxTrigFreq,406,\minAttT,0.001,\maxAttT,0.001,\minDecT,0.018,\maxDecT,0.18,\minAmp,1,\maxAmp,1,\minFreq,1280,\maxFreq,1280,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.011,\minDelTRate,0.05,\maxDelTRate,0.15,\decTC,4.72,\level,0.02,\out,1]
)
)

// sustained bowed string like variation (pure FOF synthesis -> morphFactor=1)
(
s.sendBundle(nil,
	// left channel
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,203,\maxTrigFreq,203,\minAttT,0.011,\maxAttT,0.011,\minDecT,0.035,\maxDecT,0.035,\minAmp,1,\maxAmp,1,\minFreq,494,\maxFreq,494,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.007,\minDelTRate,0.05,\maxDelTRate,0.07,\decTC,1.3,\level,0.031,\out,0],
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,101.5,\maxTrigFreq,101.5,\minAttT,0.001,\maxAttT,0.001,\minDecT,0.034,\maxDecT,0.034,\minAmp,1,\maxAmp,1,\minFreq,307,\maxFreq,307,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.007,\minDelTRate,0.05,\maxDelTRate,0.07,\decTC,0.82,\level,0.056,\out,0],
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,406,\maxTrigFreq,406,\minAttT,0.006,\maxAttT,0.006,\minDecT,0.018,\maxDecT,0.18,\minAmp,1,\maxAmp,1,\minFreq,1280,\maxFreq,1280,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.007,\minDelTRate,0.05,\maxDelTRate,0.07,\decTC,1.7,\level,0.02,\out,0],
	// right channel
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,203,\maxTrigFreq,203,\minAttT,0.011,\maxAttT,0.011,\minDecT,0.035,\maxDecT,0.035,\minAmp,1,\maxAmp,1,\minFreq,494,\maxFreq,494,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.007,\minDelTRate,0.05,\maxDelTRate,0.07,\decTC,1.3,\level,0.031,\out,1],
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,101.5,\maxTrigFreq,101.5,\minAttT,0.001,\maxAttT,0.001,\minDecT,0.034,\maxDecT,0.034,\minAmp,1,\maxAmp,1,\minFreq,307,\maxFreq,307,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.007,\minDelTRate,0.05,\maxDelTRate,0.07,\decTC,0.82,\level,0.056,\out,1],
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,406,\maxTrigFreq,406,\minAttT,0.006,\maxAttT,0.006,\minDecT,0.018,\maxDecT,0.18,\minAmp,1,\maxAmp,1,\minFreq,1280,\maxFreq,1280,\rq,1,\morphFactor,1,\minDelT,0.005,\maxDelT,0.007,\minDelTRate,0.05,\maxDelTRate,0.07,\decTC,1.7,\level,0.02,\out,1]
)
)

// sustained noise background (pure noise -> morpFactor = -1)
(
s.sendBundle(nil,
	// left channel
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,3500,\maxTrigFreq,12000,\minAttT,0.001,\maxAttT,0.002,\minDecT,0.007,\maxDecT,0.010,\minAmp,0.455,\maxAmp,1,\minFreq,67,\maxFreq,73,\rq,0.023,\morphFactor,-1,\minDelT,0.019,\maxDelT,0.021,\minDelTRate,0.07,\maxDelTRate,0.141,\decTC,0,\level,0.014,\out,0],
	// right channel
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,3500,\maxTrigFreq,12000,\minAttT,0.001,\maxAttT,0.002,\minDecT,0.007,\maxDecT,0.010,\minAmp,0.455,\maxAmp,1,\minFreq,67,\maxFreq,73,\rq,0.023,\morphFactor,-1,\minDelT,0.019,\maxDelT,0.021,\minDelTRate,0.07,\maxDelTRate,0.141,\decTC,0,\level,0.014,\out,1],
)
)

// water like
(
s.sendBundle(nil,
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,1130,\maxTrigFreq,1500,\maxAttT,0.03,\minDecT,0.01,\maxDecT,0.03,\rq,0.15,\minDelT,0.12,\maxDelT,0.3,\decT,0.5,\minDelTRate,5,\maxDelTRate,12,\out,0,\level,0.001],
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,1130,\maxTrigFreq,1500,\maxAttT,0.03,\minDecT,0.01,\maxDecT,0.03,\rq,0.15,\minDelT,0.12,\maxDelT,0.3,\decT,0.5,\minDelTRate,5,\maxDelTRate,12,\out,1,\level,0.001]
)
)

// cracked ice
(
s.sendBundle(nil,
	// left channel
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,0.525,\maxTrigFreq,1564,\minAttT,0.001,\maxAttT,0.0015,\minDecT,0.002,\maxDecT,0.0025,\minAmp,0.218,\maxAmp,1,\minFreq,478,\maxFreq,6255,\rq,0.455,\morphFactor,-1,\minDelT,0.17,\maxDelT,0.302,\minDelTRate,0.141,\maxDelTRate,1.981,\decTC,0.26,\level,0.315,\out,0],
	['/s_new',\expPulses,s.nextNodeID,0,1,\minTrigFreq,0.525,\maxTrigFreq,1564,\minAttT,0.001,\maxAttT,0.0015,\minDecT,0.002,\maxDecT,0.0025,\minAmp,0.218,\maxAmp,1,\minFreq,478,\maxFreq,6255,\rq,0.455,\morphFactor,-1,\minDelT,0.17,\maxDelT,0.302,\minDelTRate,0.141,\maxDelTRate,1.981,\decTC,0.26,\level,0.315,\out,1]
)
)

// GUI
(
var w,ctls,synthNodes,synthArgs;

ctls = [
	(name:\minTrigFreq,spec:ControlSpec(0.001,12000,\exp,0.001,10)),
	(name:\maxTrigFreq,spec:ControlSpec(0.001,12000,\exp,0.001,10)),
	(name:\minAttT,spec:ControlSpec(0.001,1,\exp,0.001,0.001)),
	(name:\maxAttT,spec:ControlSpec(0.001,1,\exp,0.001,0.1)),
	(name:\minDecT,spec:ControlSpec(0.001,1,\exp,0.001,0.001)),
	(name:\maxDecT,spec:ControlSpec(0.001,1,\exp,0.001,0.1)),
	(name:\minAmp,spec:ControlSpec(0.001,1,2,0.001,0.5)),
	(name:\maxAmp,spec:ControlSpec(0.001,1,2,0.001,1)),
	(name:\minFreq,spec:ControlSpec(20,19000,\exp,1,40)),
	(name:\maxFreq,spec:ControlSpec(20,19000,\exp,1,12000)),
	(name:\rq,spec:ControlSpec(0.001,1,2,0.001,0.7)),
	(name:\morphFactor,spec:ControlSpec(-1,1,\lin,0.001,1)),
	(name:\minDelT,spec:ControlSpec(0.001,1,2,0.001,0.01)),
	(name:\maxDelT,spec:ControlSpec(0.001,1,2,0.001,0.15)),
	(name:\minDelTRate,spec:ControlSpec(0,200,4,0.001,0.05)),
	(name:\maxDelTRate,spec:ControlSpec(0,200,4,0.001,0.15)),
	(name:\decTC,spec:ControlSpec(0,60,2,0.01,0.2)),
	(name:\level,spec:ControlSpec(0,1,2,0.001,1))
];

w = Window(\Pulses,Rect(200,200,400,400)).layout_(
	VLayout(
		View().layout_(
			HLayout(
				Button().states_([["start",Color.black,Color.green],["stop",Color.black,Color.red]]).action_({ arg butt;
					(butt.value == 0).if {
						// stop synth
						s.sendBundle(nil,*(synthNodes collect: { |node| ['/n_free',node] }));
						synthNodes = nil
					} {
						// start synth
						synthNodes = {s.nextNodeID}!2;
						synthArgs = [ctls.performUnaryOp(\name),ctls.performUnaryOp(\spec).performUnaryOp(\default)].lace(ctls.size*2);
						s.sendBundle(nil,
							['/s_new',\expPulses,synthNodes[0],1,1,\out,0] ++ synthArgs,
							['/s_new',\expPulses,synthNodes[1],1,1,\out,1] ++ synthArgs
						)
					};
				}).maxWidth_(120),
				nil
			).margins_(0)
		),
		GridLayout.rows(
			*(ctls collect: { |ctl|
				var nb = NumberBox().value_(ctl.spec.default).action_({ arg numb;
					sl.value_(ctl.spec.unmap(numb.value))
				}).decimals_(ctl.spec.step.asString.split($.)[1].size),
				sl = Slider().orientation_(\horizontal).maxHeight_(20).value_(ctl.spec.unmap(ctl.spec.default)).action_({ arg slider;
					synthNodes.notNil.if {
						s.sendBundle(nil,*(synthNodes collect: { |node| ['/n_set',node,ctl.name,ctl.spec.map(slider.value)] }))
					};
					ctl.spec.default = ctl.spec.map(slider.value);
					nb.value_(ctl.spec.map(slider.value))
				});
				[StaticText().string_(ctl.name).align_(\right),sl,nb]
			})
		).vSpacing_(4).hSpacing_(4).setColumnStretch(0,1).setColumnStretch(1,5).setColumnStretch(2,1)
	)
).front
)