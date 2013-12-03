Server.killAll

// TODO
// reimplement two servers/cores
// test multiple GUI's on one machine
// control spec for each slider type (according to notes I took earlier)
// range sliders, not individual sliders
// 'missing value' error
// set min and max refresh time bounds
// add ability to refresh by hand

/*
// create 2 servers
(
~servers = (1..2) collect: { |i| Server(\server ++ i,NetAddr("localhost",57110 + i)) };
~servers do: { |server| server.boot; server.scope }
)*/

// Autorefreshtime:
// - WARN if too low
// - what is the minimum?
// - 1.5 page still gets chance to load
// - 0.5 it doesn't (could play with this)

// - collaborative web surfing tool
// - decentralised network
// - can the browser be the driver?
// - could poll the URL
// - could poll the find string

// 0. ESSENTIALS
// - HOW TO AVOID HAVING TO TYPE SUDO PASSWORD IN TERMINAL (RUN IN BACKGROUND)
// - DON'T FORGET TO DISABLE CACHING
// - NEED TO TEST COMBO OF WIFI AND WIRED NETWORK WORKS

// 1. BASIC API
// - browse/refresh frontmost web page in Safari
// - sonically, will respond to four domains only
// - first visit will be entering URL
// - URL can then be set to refresh automatically (given rate)
// - when refreshing stops, about:blank should appear

// 2. COLLABORATIVE
// - every can start/stop each other's pages, and adjust the refresh rate timing
// - state will be stored in an OSCObjectSpace
// - one OSCObjectSpace per player
// - keys will be: \isRefreshing, \timeBetweenRefreshes
// - GUI will update based on state of the OSCObjectSpace

// 3. TIMING
// - one player will be the master
// - everyone starts as 'slave' by default
// - clock data will be sent in the form /time seconds
// - this can be mapped to a clock which runs from 0 to 15 minutes
// - as well as a position marker in the piece, from 0 to 1
// - decide on a collective tempo (could be adjusted)

// 4. CHAT
// - basic chat module might help (relay?)

// 5. DOMAIN/SYNTHGUI's
// website GUIs
// - a gui for each domain
// - each will have:
// - some
// - wet/dry
// - amp

(
// PACKET ANALYSIS + SONIFICATION

~initPacketAnalyser = {
	"sudo killall python; sudo /usr/bin/python ~/Desktop/Amalgam/github/packet-analyser.py".runInTerminal;
	// wait time?
};

~initDisplayOSCFuncs = {
	~sonificationOscPaths.collect{arg oscPath;
		OSCFunc({arg msg;
			var playerName, parameters;
			playerName = msg[1];
			parameters = msg.drop(2);
			case
			{oscPath == '/start'} {
				var host, path;
				# host, path = parameters;
				msg.postln;
				[host, host.class.postln];
				if (~domainToSynthMappingDict.keys.includes(host)) {
					defer {
						~domainToSynthMappingDict.at(host).at(\domainLabel).background_(Color.green);
						[playerName, playerName.class].postln;
						~expectedPlayerDict.at(playerName).at(\hostLabel).string_(host);
						~expectedPlayerDict.at(playerName).at(\pathLabel).string_(path);
					};
				};
			}
			{oscPath == '/stop'} {
				var host, path;
				# host, path = parameters;
				msg.postln;
				if (~domainToSynthMappingDict.keys.includes(host)) {
					defer {
						~domainToSynthMappingDict.at(host).at(\domainLabel).background_(Color.white);
						~expectedPlayerDict.at(playerName).at(\hostLabel).string_(host);
						~expectedPlayerDict.at(playerName).at(\pathLabel).string_(path);
					};
				};
			};
		}, oscPath);
	};
};

~initSonificationOSCFuncs = {
	~sonificationOscPaths.collect{arg oscPath;
		OSCFunc({arg msg;
			var playerName, parameters;
			playerName = msg[1];
			parameters = msg.drop(2);
			if (~playerStreamButtonDict.at(playerName)) { // if is true
				case
				{oscPath == '/start'} {
					var host, path;
					# host, path = parameters;
					if (~synth.isPlaying) {~synth.free};
					~synth = Synth(host,[\out,10],s,'addToHead');
					NodeWatcher.register(~synth);
					// if (~allowedHosts.includes(host.asSymbol)) {};
				}
				{oscPath == '/stop'} {
					var host, path;
					# host, path = parameters;
					~synth.free;
					// if (~allowedHosts.includes(host.asSymbol)) {};
				}
			};
		}, oscPath);
	};
};

// BROWSING FUNCTIONS:

~initSafari = {
	// beware, two copies of Safari can run at the same time!
	// so do 'if not open'
	// disable caching here
	"osascript -e 'tell application \"Safari\" to activate'".unixCmd;
	"osascript -e 'tell application \"Safari\" to set the URL of the front document to \"about:blank\"'".unixCmd;
};

~startRefreshing = {
	~refreshRoutine= Routine({
		inf.do{
			"osascript -e 'tell application \"Safari\"' -e 'do JavaScript \"location.reload(true)\" in document 1' -e 'end tell'".unixCmd;
			~autoRefreshTime.wait;
		}
	}).play(SystemClock)
};

~stopRefreshing = {
	~refreshRoutine.stop;
	"osascript -e 'tell application \"Safari\" to set the URL of the front document to \"about:blank\"'".unixCmd;
};

~startPollingCurrentURL = {
	var pollRate = 1;
	~pollRoutine = Routine({
		inf.do{
			// 3. get current URL
			fork {
				var url;
				url = "osascript -e 'tell application \"Safari\" to return the URL of the front document'".unixCmdGetStdOut;
				url = url.drop(-1); // drop trailing carriage return
				defer { ~playerRowViews[0].children[1].string_(url) };
			};
			pollRate.wait;
		}
	}).play;
};

// COLLABORATIVE BROWSING FUNCTIONS:

~setRefreshState = {arg playerName, refreshState;
	var dataSpace;
	dataSpace = ~playerDataSpaces.at(playerName);
	dataSpace.put(\refreshState, refreshState);
};

~setRefreshRate = {arg playerName, refreshRate;
	var dataSpace;
	dataSpace = ~playerDataSpaces.at(playerName);
	dataSpace.put(\refreshRate, refreshRate);
};

// GUI FUNCTIONS:

~makeMainGUI = {
	var clockGUI, webGUI, domainPane;
	clockGUI = ~makeClockGUI.value;
	webGUI = ~makeWebGUI.value;
	domainPane = ~makeDomainPane.value;
	View(nil, Window.screenBounds).layout_(VLayout(
		[clockGUI.background_(Color.blue(alpha:0.2)), stretch: 1],
		[webGUI.background_(Color.green(alpha:0.2)), stretch: 2],
		[domainPane.background_(Color.magenta(alpha:0.2)), stretch: 15]
	).spacing_(0).margins_(0));
};


~makeClockGUI = {
	var domainDict, titleText, slaveMasterButton, startStopButton, clockDisplay;

	titleText = StaticText().string_("Clock:");
	slaveMasterButton = Button()
	.states_([["master"], ["slave"]])
	.action_({arg button;
		if (button.value == 1) {
			startStopButton.states_([["start"],["stop"]])
		} {
			startStopButton.states_([[]]);
		};
	});
	startStopButton = Button()
	.states_([])
	.action_({arg button;
		if (button.value == 1) {
			~initAndStartClock.value;
		}
		{
			~stopClock.value;
		}
	});
	clockDisplay = StaticText()
	.font_(Font("Monaco", 30))
	.string_("00:00");
	~clockDisplay = clockDisplay;
	View().layout_(HLayout(titleText, slaveMasterButton, startStopButton, clockDisplay)
		.spacing_(10).margins_(0)
	);

};

~makeWebGUI = {
	var titleRow, refreshRows;
	titleRow = ~makeTitleRow.value;
	refreshRows = ~expectedPlayerNames.collect({arg expectedPlayerName;
		~makeRefreshRow.value(expectedPlayerName);
	});
	View().layout_(VLayout(*
		[titleRow] ++ refreshRows
	).spacing_(0).margins_(0)
	);
};

~makeTitleRow = {
	var playerTitle, hostTitle, pathTitle, refreshTitle, refreshTimeTitle;
	playerTitle = StaticText().string_("player:");
	hostTitle = StaticText().string_("host:");
	pathTitle = StaticText().string_("path:");
	refreshTitle = StaticText().string_("refresh:");
	refreshTimeTitle = StaticText().string_("refresh time:");
	View().layout_(HLayout(
		[playerTitle, stretch: ~stretch[0]],
		[hostTitle, stretch: ~stretch[1]],
		[pathTitle, stretch: ~stretch[1]],
		[refreshTitle, stretch: ~stretch[2]],
		[refreshTimeTitle, stretch: ~stretch[3]]
	).spacing_(0).margins_(0));
};

~makeRefreshRow = {arg playerName;
	var playerNameLabel, hostLabel, pathLabel, refreshButton, refreshTime;
	playerNameLabel = StaticText().string_(playerName).background_(Color.white);
	~expectedPlayerDict.at(playerName).put(\onlineView, playerNameLabel);
	hostLabel = StaticText().background_(Color.white);
	~expectedPlayerDict.at(playerName).put(\hostLabel, hostLabel);
	pathLabel = StaticText().background_(Color.white);
	~expectedPlayerDict.at(playerName).put(\pathLabel, pathLabel);
	refreshButton = Button()
	.states_([
		["start", Color.black, Color.white],
		["stop", Color.black, Color.green(alpha:0.2)]
	])
	.action_({arg button;
		~setRefreshState.value(playerName, button.value.asBoolean);
	});
	~expectedPlayerDict.at(playerName).put(\refreshButton, refreshButton);
	refreshTime = NumberBox().minWidth_(50)
	.value_(~autoRefreshTime)
	.action_({arg numberBox;
		~setRefreshRate.value(playerName, numberBox.value);
	});
	View().layout_(HLayout(
		[playerNameLabel, stretch: ~stretch[0]],
		[hostLabel, stretch: ~stretch[1]],
		[pathLabel, stretch: ~stretch[1]],
		[refreshButton, stretch: ~stretch[2]],
		[refreshTime, stretch: ~stretch[3]]
	).spacing_(10).margins_(0));
};

~makeDomainPane = {
	var domainColumns;
	domainColumns = ~alphabeticalDomains.collect{arg domain;
		var domainDict, domainLabel, synthDefNameLabel, paramViews;
		domainDict = ~domainToSynthMappingDict.at(domain);
		domainLabel = StaticText()
		.string_(domain)
		.align_(\center)
		.background_(Color.white);
		synthDefNameLabel = StaticText()
		.string_(domainDict.synthDefName)
		.align_(\center)
		.background_(Color.white);
		paramViews = domainDict.params.collect({arg paramName;
			var paramNameLabel, paramSlider, paramNumberBox;
			paramNameLabel = StaticText()
			.string_(paramName);
			paramSlider = Slider().orientation_(\horizontal)
			.action_({arg slider;
				paramNumberBox.value_(slider.value);
				if (~synth.isPlaying) {
					~synth.set(paramName, slider.value);
				};
			});
			paramNumberBox = NumberBox()
			.enabled_(false);
			View().layout_(HLayout(
				[paramNameLabel, stretch: 2],
				[paramSlider, stretch: 6],
				[paramNumberBox, stretch: 1]
			)
			.spacing_(0)
			.margins_(0)
			);
		});
		domainDict.put(\domainLabel, domainLabel);
		View().layout_(VLayout(*([domainLabel, synthDefNameLabel] ++ paramViews ++ [nil]))
			.spacing_(3)
			.margins_(0)
		)
	};
	View(nil, Rect(0, 0, 800, 400)).layout_(GridLayout.rows(*domainColumns.clump(2))
		.spacing_(3)
		.margins_(0)
	);

};

// CLOCK FUNCTIONS:

~initAndStartClock = {
	~clockRoutine !? {~clockRoutine.free}; // prevent multiple clocks
	~clockRoutine = Routine({
		var now;
		now = Main.elapsedTime; // do this on startup
		inf.do{
			var currentTimeInSeconds, minutes, seconds, minuteString, secondString, displayString, msgToSend;
			currentTimeInSeconds = Main.elapsedTime - now;
			~globalDataSpace.put(\currentTimeInSeconds, currentTimeInSeconds);
			1.wait;
		};
	}).play(SystemClock) // can run thru cmd + period?
};

~stopClock = {
	~clockRoutine.stop;
};

~makeTimeString = {arg time; // minutes or seconds;
	if (time.asString.size == 1) { "0" ++ time.asString } { time.asString }
};

~initAddrBookDependencies = {
	~myNode.addrBook.addDependant({arg addrBook, what, who;
		case
		{ what == \registeredName } {
			defer {
				var onlineView;
				onlineView = ~expectedPlayerDict.at(who.name).at(\onlineView);
				onlineView.background_(~onlineColor);
			};
		}
		{ what == \wentOffline } {
			defer {
				var onlineView;
				onlineView = ~expectedPlayerDict.at(who.name).at(\onlineView);
				onlineView.background_(~offlineColor);
			};
		};
	});
};

~initGlobalDataSpace = {
	~globalDataSpace = OSCDataSpace(~myNode.addrBook, ~myNode.me, '/globalDataSpace');
	~globalDataSpace.addDependant({arg dataSpace, val, key, value;
		case
		{ key == \currentTimeInSeconds } {
			var currentTime, minutes, seconds, minuteString, secondString, displayString, msgToSend;
			// + 1 here to account for title row
			currentTime = value;
			minutes = (currentTime/60).asInt;
			seconds = (currentTime%60).asInt;
			minuteString = ~makeTimeString.value(minutes);
			secondString = ~makeTimeString.value(seconds);
			displayString = minuteString ++ ":" ++ secondString;
			defer {
				~clockDisplay.string_(displayString);
			};
		};
	});
};

~initPlayerDataSpaces = {
	~playerDataSpaces = ();
	~expectedPlayerNames.do({arg expectedPlayerName;
		var playerDataSpace;
		playerDataSpace = OSCDataSpace(~myNode.addrBook, ~myNode.me, expectedPlayerName);
		~initDependancyHandler.value(expectedPlayerName, playerDataSpace);
		~playerDataSpaces.put(expectedPlayerName, playerDataSpace);
	});
};

~initDependancyHandler = {arg expectedPlayerName, playerDataSpace;
	playerDataSpace.addDependant({arg dataSpace, val, key, value;
		[dataSpace, val, key, value].postln;
		case
		{ key == \refreshState } {
			// update GUI:
			var refreshButton;
			refreshButton = ~expectedPlayerDict.at(expectedPlayerName).at(\refreshButton);
			defer { refreshButton.value_(value.asInt); };
			// perform action if me:
			if (expectedPlayerName == ~myName) {
				if (value == true) {
					~startRefreshing.value;
				} {
					~stopRefreshing.value;
				};
			};
		}
		{ key == \refreshRate } {
			// update GUI:
			var refreshRateBox;
			refreshRateBox = ~expectedPlayerDict.at(expectedPlayerName).at(\refreshRateBox);
			defer { refreshRateBox.value_(value); };
			// perform action if me:
			if (expectedPlayerName == ~myName) {
				~autoRefreshTime = value;
			};
		}
	});
};

// SYNTHDEF FUNCTIONS:

~initResonatorSynthDefs = {
	var sdFunc;
	sdFunc = { |sdName,n|
		SynthDef(sdName,{ arg in,out=0,preGain=1,postGain=1,xfade=1;
			var a1,a2,b1,b2,output,input;
			a1 = Control.names(\a1).kr({0}!n);
			a2 = Control.names(\a2).kr({0}!n);
			b1 = Control.names(\b1).kr({0}!n);
			b2 = Control.names(\b2).kr({0}!n);
			input = In.ar(in,1)*preGain;
			output = SOS.ar(input,0,a1,a2,b1,b2).sum*postGain;
			Out.ar(out,LinXFade2.ar(input,output.tanh,xfade))
		}).add;
	};
	3 do: { |i| sdFunc.(\string_ ++ (i + 1),~network.modalData.numModes[i][i]) }
};

~initExcitationSynthDefs = {

	SynthDef(\bandNoise,{ arg out=0,amp=1,freqLo=50,freqHi=12000,freqModT=3e-02,gate=1,doneAct=2,cutoffHp=80,cutoffLp=1e4,attT=6,decT=8,attC=2,decC= -2,bwLo=0.5,bwHi=1.5;
		var source = PinkNoise.ar(1),env;
		env = EnvGen.kr(Env([0,1,0],[attT,decT],[attC,decC]),doneAction:doneAct);
		25 do: { source = BBandStop.ar(source,LFDNoise1.kr(freqModT).exprange(freqLo,freqHi),ExpRand(bwLo,bwHi)) };
		Out.ar(out,HPF.ar(LPF.ar(source,cutoffLp,amp*env),cutoffHp))
	}).add;

	SynthDef(\noisePulseCluster, { arg out=0,minDelT=0.001,maxDelT=0.02,minDecT=0.007,maxDecT=0.02,minAmp=0.1,maxAmp=0.7,freqLo=400,freqHi=19000,rq=0.1,minTrigFreq=0.01,maxTrigFreq=50,decT=8,relT=1,doneAct=14,gate=1;
		var output,trig;
		Linen.kr(gate,0.01,1,relT,doneAct);
		trig = LocalIn.ar(1);
		trig = Impulse.ar(TExpRand.ar(minTrigFreq,maxTrigFreq,trig));
		trig = CombN.ar(trig,0.2,LFDNoise0.kr(3.14).range(0.07,0.2).lag(5e3),decT);
		LocalOut.ar(trig);
		output = Decay.ar(trig,TExpRand.ar(minDecT,maxDecT,trig),WhiteNoise.ar(TExpRand.ar(minAmp,maxAmp,trig)));
		2 do: { output = Resonz.ar(output,TExpRand.ar(freqLo,freqHi,trig),rq.lag(0.01)) };
		Out.ar(out,Limiter.ar(output*rq.sqrt.reciprocal,0.97,0.01))
	}).add;

	SynthDef(\noisePulses,{ arg out=0,loDens=10,hiDens=100,loRattle=0.001,hiRattle=0.4,loRattleRate=30,hiRattleRate=100,loGrainSize=0.0001,hiGrainSize=0.05,relAttT=0.5,bw=1,loFreq=200,hiFreq=12000,decT=0.001,amp=1,t_trig=1;
		var overlap=4,dens,trig,env,output;
		dens = LFDNoise1.ar(LFDNoise1.kr(0.5).range(0.1,10)).exprange(loDens,hiDens);
		trig = {TDelay.ar(K2A.ar(t_trig),Rand(0.005,0.1))}!overlap;
		env = EnvGen.ar(Env.perc(0,1,curve:TRand.ar(-8,8,trig)),trig,timeScale:TExpRand.ar(loRattle,hiRattle,trig));
		trig = env.sqrt*Dust.ar(TExpRand.ar(loRattleRate,hiRattleRate));
		env = EnvGen.ar(Env.perc(relAttT,1-relAttT,curve:TExpRand.ar(4,12,trig).neg),trig,Latch.ar(trig,trig),
			timeScale:TExpRand.ar(loGrainSize,hiGrainSize,trig));
		output = BBandPass.ar(WhiteNoise.ar(env).sum,TExpRand.ar(loFreq,hiFreq,trig),bw);
		Out.ar(out,(Ringz.ar(output,({exprand(50,14000)}!16).sort,({exprand(0.01,1)}!16).sort.reverse*decT,({exprand(0.1,1.0)}!16).sort).sum*amp).tanh)
	}).add;
};

// SYNTH FUNCTIONS:

~initResonatorSynths = {
	var nwNode = i=0,j=1,k=2;

	// string one
	Synth(\string_ ++ (i + 1),[\in,10,\out,0,\postGain,6.dbamp,\xfade,1,\a1,~network.modalData.biquadCoefs.a1[i][i],\a2,~network.modalData.biquadCoefs.a2[i][i],\b1,~network.modalData.biquadCoefs.b1[i][i].neg,\b2,~network.modalData.biquadCoefs.b2[i][i].neg],s,'addToTail');

	// string two
	Synth(\string_ ++ (j + 1),[\in,10,\out,0,\postGain,6.dbamp,\xfade,1,\a1,~network.modalData.biquadCoefs.a1[j][j],\a2,~network.modalData.biquadCoefs.a2[j][j],\b1,~network.modalData.biquadCoefs.b1[j][j].neg,\b2,~network.modalData.biquadCoefs.b2[j][j].neg],s,'addToTail');

	// string three
	Synth(\string_ ++ (k + 1),[\in,10,\out,0,\postGain,6.dbamp,\xfade,1,\a1,~network.modalData.biquadCoefs.a1[k][k],\a2,~network.modalData.biquadCoefs.a2[k][k],\b1,~network.modalData.biquadCoefs.b1[k][k].neg,\b2,~network.modalData.biquadCoefs.b2[k][k].neg],s,'addToTail');
};

// OTHERS:

~initAndStartFakeWebActivityRoutine = {
	Routine({
		inf.do{
			var chosenDomain, domainDict, domainLabel;
			chosenDomain = ~alphabeticalDomains.choose;
			domainDict = ~domainToSynthMappingDict.at(chosenDomain);
			// activity on GUI here
			defer {
				domainLabel = domainDict.at(\domainLabel);
				domainLabel.background_(Color.green);
			};
			if (~synth.isPlaying) {~synth.free};
			~synth = Synth(domainDict.synthDefName,[\out,10],s,'addToHead');
			NodeWatcher.register(~synth);
			rrand(4, 8).wait;
			~synth.free;
			defer {
				domainLabel.background_(Color.white);
			};
			rrand(1, 2).wait;
		};
	}).play
};

~initNode = {
	var me;
	~myNode.register(~myName);
	~initAddrBookDependencies.value;
	~initGlobalDataSpace.value;
	~initPlayerDataSpaces.value;
	// read in modal data
	~network = FDObjNetwork.loadObjNetwork(
		"/Users/grahambooth/Desktop/Amalgam/PMNetwork/network.scd" // hard coding for now
		// thisProcess.nowExecutingPath.dirname ++ "/network.scd"
	);
	s.waitForBoot({
		~initResonatorSynthDefs.value;
		s.sync;
		~initExcitationSynthDefs.value;
		s.sync;
		~initResonatorSynths.value;
		s.sync;
		//~initAndStartFakeWebActivityRoutine.value;
	});
};

// MAIN:

// variables:
~domainToSynthMappingDict = (
	'en.wikipedia.org':
	(
		synthDefName: \bandNoise,
		params: [\freqLo, \freqHi, \cutoffHp, \cutoffLp, \amp],
		domainLabel: nil
	),
	'www.google.com':
	(
		synthDefName: \noisePulses,
		params: [\loRattle, \hiRattle, \loRattleRate, \hiRattleRate, \loFreq, \hiFreq, \amp],
		domainLabel: nil
	),
	'www.bing.com':
	(
		synthDefName: \noisePulseCluster,
		params: [\freqLo, \freqHi, \rq, \minTrigFreq, \maxTrigFreq, \amp],
		domainLabel: nil
	),
	'www.wolframalpha.com':
	(
		synthDefName: \noisePulseCluster,
		params: [\freqLo, \freqHi, \rq, \minTrigFreq, \maxTrigFreq, \amp],
		domainLabel: nil
	);
);
~clockDisplay = nil;
~alphabeticalDomains = ~domainToSynthMappingDict.keys.asArray.sort;
~myName = \graham;
~expectedPlayerNames = [\aidan, \graham, \michael, \robin];
~expectedPlayerDict = (
	aidan: (onlineView: nil, \refreshButton: nil, \refreshRateBox: nil),
	graham: (onlineView: nil, \refreshButton: nil, \refreshRateBox: nil),
	michael: (onlineView: nil, \refreshButton: nil, \refreshRateBox: nil),
	robin: (onlineView: nil, \refreshButton: nil, \refreshRateBox: nil)
);
~sonificationOscPaths = ['/start', '/progress', '/searchResults', '/bodyLength', '/body', '/stop'];
~onlineColor = Color.green(alpha: 0.3);
~offlineColor = Color.black;
~stretch = [3, 6, 2, 1];
~autoRefreshTime = 1;

// 1. make the GUI:
~mainGUI !? { ~mainGUI.destroy };
~mainGUI = ~makeMainGUI.value.front;

// 2. init sonification:
~initPacketAnalyser.value;
~displayOSCFuncs !? { ~displayOSCFuncs.do{arg oscFunc; oscFunc.free} };
~displayOSCFuncs = ~initDisplayOSCFuncs.value;
~sonificationOSCFuncs !? { ~sonificationOSCFuncs.do{arg oscFunc; oscFunc.free} };
~sonificationOSCFuncs = ~initSonificationOSCFuncs.value;

// 2. go online:
~myNode = NMLDecentralisedNode(doWhenMeAdded: ~initNode ); // survive command period
//~initNode.value;
)

s.queryAllNodes

// LEFTOVERS:

// Applescripts:
// 1. refresh current page in background
"osascript -e 'tell application \"Safari\"' -e 'do JavaScript \"location.reload(true)\" in document 1' -e 'end tell'".unixCmd;
// 2. go to 'about blank'
"osascript -e 'tell application \"Safari\" to set the URL of the front document to \"about:blank\"'".unixCmd;
// 3. get current URL
"osascript -e 'tell application \"Safari\" to return the URL of the front document'".unixCmd;
// 4. get find command

// SYNTH GUI's

RangeSlider(nil, Rect(0, 0, 200, 20)).orientation_(\horizontal).front
EnvelopeView().front
(
// use shift-click to keep a node selected
w = Window("envelope", Rect(150 , Window.screenBounds.height - 250, 250, 100)).front;
w.view.decorator = FlowLayout(w.view.bounds);

b = EnvelopeView(w, Rect(0, 0, 230, 80))
.drawLines_(true)
.selectionColor_(Color.red)
.drawRects_(true)
.resize_(5)
.step_(0.05)
.action_({arg b; [b.index, b.value].postln})
.thumbSize_(5)
.value_([[0.0, 0.1, 0.5, 1.0],[0.1,1.0,0.8,0.0]]);
w.front;


