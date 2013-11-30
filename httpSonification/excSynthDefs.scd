(
SynthDef(\bandNoise,{ arg out=0,amp=1,freqLo=50,freqHi=12000,freqModT=3e-02,gate=1,doneAct=2,cutoffHp=80,cutoffLp=1e4,relT=1,attT=6,decT=8,attC=2,decC= -2;
	var source = PinkNoise.ar(1),env;
	env = EnvGen.kr(Env([0,1,0],[attT,decT],[attC,decC]),doneAction:doneAct);
	25 do: { source = BBandStop.ar(source,LFDNoise1.kr(freqModT).exprange(freqLo,freqHi),ExpRand(0.5,1.5)) };
	Out.ar(out,HPF.ar(LPF.ar(source,cutoffLp,amp*env),cutoffHp))
}).add;

SynthDef(\shuffledNoise, { arg out=10,ampModFreq=10,freqModFreq=10,noiseModFreq=20,loFreq=500,hiFreq=14000,rq=0.75,amp=1,curve=2,gate=1,relT=1,doneAct=2;
	var output = ({Resonz.ar(PinkNoise.ar(LFNoise1.ar(noiseModFreq,0.5,0.5).squared ! 2),
	LFDNoise1.ar(freqModFreq).exprange(loFreq,hiFreq),rq)}!25).sum*(LFNoise2.ar(ampModFreq)**curve).abs.clip(0,rq.reciprocal.sqrt);
	Linen.kr(gate,0.01,1,relT,doneAct);
	Out.ar(out,output*amp)
}).add;

SynthDef(\pulsedNoise, { arg out=10,thresh1=0.25,thresh2=0.5,pulseFreq=100,hpFreq=1050,lpFreq=5270,amp=1,gate=1,doneAct=2;
	var output = WhiteNoise.ar(thresh1 > (WhiteNoise.ar.abs ! 2));
	Linen.kr(gate,0.01,1,1,doneAct);
	Out.ar(out,HPF.ar(LPF.ar(output,lpFreq,thresh2 > LFSaw.ar(pulseFreq,0,0.5,0.5)),hpFreq,amp))
}).add;

SynthDef(\delayedPulses, { arg out=0,freqMin=200,freqMax=12000,attMin=0.001,attMax=0.003,decMin=0.003,decMax=0.007,dens=2,delMin=0.05,delMax=0.17,rq=0.5,decTime=0.9,modSpeed=0.01,modMin=0.1,modMax=0.3,amp=1,gate=1,doneAct=2;
	var imp=Dust2.ar(dens),output,num=5,del;
	Linen.kr(gate,0.01,1,1,doneAct);
	del = Control.names([\del]).kr(Array.fill(num,{ rrand(0.1,0.8) }));
	output = { |i|
		Mix.fill(num,{ |k| var trig,source;
			trig = TDelay.ar(imp,del[k]*TRand.ar(delMin,delMax,imp));
			source = LeakDC.ar(RHPF.ar(Decay2.ar(trig,TExpRand.ar(attMin,attMax,trig),TExpRand.ar(decMin,decMax,imp),
				WhiteNoise.ar(amp)),TExpRand.ar(500,12000,trig),0.2),0.92,TRand.ar(0,1,trig)**2);
			source = Resonz.ar(source,TExpRand.ar(freqMin,freqMax,trig),rq.lag(0.01),rq.reciprocal)
		})
	} ! 2;
	6 do: { output = AllpassC.ar(output,1.0,LFDNoise3.kr(modSpeed).range(modMin,modMax),decTime) };
	Out.ar(out,Limiter.ar(output,0.99,0.01));
}).add;

SynthDef(\noisePulseCluster, { arg out=0,minDelT=0.001,maxDelT=0.02,minDecT=0.007,maxDecT=0.02,minAmp=0.1,maxAmp=0.7,freqLo=400,freqHi=19000,rq=0.1,minTrigFreq=0.01,maxTrigFreq=50,decT=8,relT=1,doneAct=14,gate=1;
	var output,trig;
	Linen.kr(gate,0.01,1,relT,doneAct);
	trig = LocalIn.ar(2);
	trig = { Impulse.ar(TExpRand.ar(minTrigFreq,maxTrigFreq,trig.sum)) } ! 2;
	trig = CombN.ar(trig,0.2,LFDNoise0.kr(3.14).range(0.07,0.2).lag(5e3),decT);
	LocalOut.ar(trig);
	output = Decay.ar(trig,TExpRand.ar(minDecT,maxDecT,trig),WhiteNoise.ar(TExpRand.ar(minAmp,maxAmp,trig)));
	2 do: { output = Resonz.ar(output,TExpRand.ar(freqLo,freqHi,trig),rq.lag(0.01)) };
	Out.ar(out,Limiter.ar(output*rq.sqrt.reciprocal,0.97,0.01))
}).add;

SynthDef(\noisePulses,{ arg out=0,loDens=10,hiDens=100,loRattle=0.001,hiRattle=0.4,loRattleRate=30,hiRattleRate=100,loGrainSize=0.0001,hiGrainSize=0.05,relAttT=0.5,rq=1,loHpFreq=200,hiHpFreq=3500,loLpFreq=4000,hiLpFreq=16000,decT=0.001,amp=1;
	var overlap=4,dens,trig,env,output;
	dens = LFDNoise1.ar(LFDNoise1.kr(0.5).range(0.1,10)).exprange(loDens,hiDens);
	trig = {Dust.ar(dens/overlap)}!overlap;
	env = EnvGen.ar(Env.perc(0,1,curve:TRand.ar(-8,8,trig)),trig,timeScale:TExpRand.ar(loRattle,hiRattle,trig));
	trig = env.sqrt*Dust.ar(TExpRand.ar(loRattleRate,hiRattleRate));
	env = EnvGen.ar(Env.perc(relAttT,1-relAttT,curve:TExpRand.ar(4,12,trig).neg),trig,Latch.ar(trig,trig),
		timeScale:TExpRand.ar(loGrainSize,hiGrainSize,trig));
	output = RLPF.ar(RHPF.ar(WhiteNoise.ar(env).sum,TExpRand.ar(loHpFreq,hiHpFreq,trig),rq),TExpRand.ar(loLpFreq,hiLpFreq,trig),rq);
	Out.ar(out,(Ringz.ar(output,({exprand(50,14000)}!16).sort,({exprand(0.01,1)}!16).sort.reverse*decT,({exprand(0.1,1.0)}!16).sort).sum*amp).tanh)
}).add
)