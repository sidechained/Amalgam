s.boot; s.scope(2)
(
SynthDef(\determExpPulses,{ arg
	out=0,
	trigFreq=0.5,
	attT=0.5,
	decT=0.5,
	freq=1000,
	rq=0.7,
	decTC=0.2,
	delT=0.10,
	delTRate=0.10,
	amp=0.5,
	level=1,
	morphFactor=1;
	var trig,noise,fof,signal;
	trig = LocalIn.ar(1);
	trig = Impulse.ar(trigFreq);
	LocalOut.ar(trig);
	noise = Resonz.ar(Decay2.ar(trig,attT,decT,WhiteNoise.ar(amp)),freq,rq)*rq.reciprocal;
	fof = Formlet.ar(trig,freq,attT,decT,amp);
	signal = LinXFade2.ar(noise,fof,morphFactor);
	signal = CombC.ar(signal,1,delT,decTC);
	Out.ar(out,signal*level)
}).add;
)


// GUI
(
var w,ctls,synthNodes,synthArgs;

ctls = [
	(name:\trigFreq,spec:ControlSpec(0.001,12000,\exp,0.001,10)),
	(name:\attT,spec:ControlSpec(0.001,1,\exp,0.001,0.1)),
	(name:\decT,spec:ControlSpec(0.001,1,\exp,0.001,0.1)),
	(name:\amp,spec:ControlSpec(0.001,1,2,0.001,1)),
	(name:\freq,spec:ControlSpec(20,19000,\exp,1,12000)),
	(name:\rq,spec:ControlSpec(0.001,1,2,0.001,0.7)),
	(name:\morphFactor,spec:ControlSpec(-1,1,\lin,0.001,1)),
	(name:\delT,spec:ControlSpec(0.001,1,2,0.001,0.15)),
	(name:\delTRate,spec:ControlSpec(0,200,4,0.001,0.15)),
	(name:\decTC,spec:ControlSpec(0,60,2,0.01,0.2)),
	(name:\level,spec:ControlSpec(0,1,2,0.001,1))
];

w = Window(\Pulses,Rect(200,200,400,400)).layout_(
	VLayout(
		View().layout_(
			HLayout(
				Button().states_([["start",Color.black,Color.green],["stop",Color.black,Color.red]]).action_({ arg butt;
					(butt.value == 1).if {
						// start synth
						synthArgs = [ctls.performUnaryOp(\name),ctls.performUnaryOp(\spec).performUnaryOp(\default)].lace(ctls.size*2);
						synthNodes = [
							Synth(\determExpPulses, [\out, 0] ++ synthArgs),
							Synth(\determExpPulses, [\out, 1] ++ synthArgs)
						];
					} {
						// stop synth
						synthNodes !? {
							synthNodes.do{arg synthNode; synthNode.free };
							synthNodes = nil;
						};
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
					synthNodes !? {
						synthNodes.do{arg synthNode;
							synthNode.set(ctl.name,ctl.spec.map(slider.value));
							synthNode.set(ctl.name,ctl.spec.map(slider.value));
						}
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