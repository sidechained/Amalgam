// TODO:

//http://new-supercollider-mailing-lists-forums-use-these.2681727.n2.nabble.com/Error-when-loading-Scipy-module-in-Python-script-from-SC-on-OSX-10-6-8-works-on-10-7-5-td7590547.html

//"/usr/bin/python ~/Desktop/Amalgam/github/packet-analyser.py".systemCmd; // syncronously
//"kill -9 6865".unixCmd

// list of IP's goes here:
// graham: 143.117.177.118

(
s.waitForBoot({

	// load python script (running in terminal for now to watch for errors)
	// may have to enter sudo password (how to get around this? is needed to capture packets)
	"sudo killall python; sudo /usr/bin/python ~/Desktop/Amalgam/github/packet-analyser.py".runInTerminal;
	~expectedPlayerNames = [\aidan, \michael, \graham, \robin];
	~playerPacketByteRanges = ();
	~playerHostLabels = ();
	~playerPathLabels = ();
	~playerActivityViews = ();
	~playerStreamButtonDict = ();
	~runningSynths = ();

	// hosts
	~allowedHosts = ['www.openbsd.org', 'www.freebsd.org', 'www.manpagez.com'];
	// init OSCFuncs
	~oscPaths = ['/start', '/stop', '/host', '/path', '/packetByteRange', '/data'];
	~displayOSCFuncs !? { ~displayOSCFuncs.do{arg oscFunc; oscFunc.free} };
	~displayOSCFuncs = ~oscPaths.collect{arg oscPath;
		OSCFunc({arg msg;
			var playerName, parameters;
			playerName = msg[1];
			parameters = msg.drop(2);
			case
			{oscPath == '/start'} {
				var host, path;
				# host, path = parameters;
				defer {
					~playerActivityViews.at(playerName).clearDrawing;
					~playerHostLabels.at(playerName).string_(host);
					~playerPathLabels.at(playerName).string_(path);
				};
			}
			{oscPath == '/packetByteRange' } {
				~playerPacketByteRanges.put(playerName, parameters);
				defer { ~playerActivityViews.at(playerName).refresh };
			}
			{oscPath == '/data'} {
				var data;
				data = parameters[0];
				defer {
					~dataPane.string_(data);
				};
			};
		}, oscPath);
	};

	~sonificationOSCFuncs !? { ~sonificationOSCFuncs.do{arg oscFunc; oscFunc.free} };
	~sonificationOSCFuncs = ~oscPaths.collect{arg oscPath;
		OSCFunc({arg msg;
			var playerName, parameters;
			playerName = msg[1];
			parameters = msg.drop(2);
			if (~playerStreamButtonDict.at(playerName)) { // if is true
				\getsHere.postln;
				case
				{oscPath == '/start'} {
					var host, path;
					# host, path = parameters;
					msg.postln;
					if (~allowedHosts.includes(host.asSymbol)) {
						var synth, synthKey;
						synthKey = host + path;
						("startingSynth" + synthKey).postln;
						synth = Synth(host);
						~runningSynths.put(synthKey, synth)
					};
				}
				{oscPath == '/stop'} {
					var host, path;
					msg.postln;
					# host, path = parameters;
					if (~allowedHosts.includes(host.asSymbol)) {
						var synthKey;
						synthKey = host + path;
						("stoppingSynth" + synthKey).postln;
						~runningSynths.at(synthKey).free
					};
				}
			};
		}, oscPath);
	};

	~sonificationOSCFuncs.postln;

	~maxTransferLength = 40000; // in bytes?
	~activityRows = ~expectedPlayerNames.collect{arg expectedPlayerName;
		var playerLabel, hostLabel, pathLabel, activityView, mapButton, mapButtonsView;
		playerLabel = StaticText()
		.string_(expectedPlayerName.asString ++ "'s browser")
		.maxWidth_(70)
		.background_(Color.white);
		hostLabel = StaticText()
		.font_(Font("Monaco", 9))
		.maxWidth_(200)
		.align_(\topLeft)
		.background_(Color.white);
		pathLabel = StaticText()
		.font_(Font("Monaco", 9))
		.align_(\topLeft)
		.maxWidth_(200)
		.background_(Color.white);
		activityView = UserView()
		.drawFunc_({arg userView;
			// map bytes to pixels
			// as we typically cannot know the length of a transfer before sending, we must set an arbitrary length that we imagine as the maximum transfer length
			// each time we get a body message, we should
			// byteProgress
			var startX, endX;
			~playerPacketByteRanges.at(expectedPlayerName) !? {
				// might not react to every transfer
				# startX, endX = ~playerPacketByteRanges.at(expectedPlayerName).linlin(0, ~maxTransferLength, 0, userView.bounds.width);
				Pen.fillColor_(Color.black);
				Pen.fillRect(Rect(startX, 0, endX - startX, userView.bounds.height));
			}
		})
		.minHeight_(40)
		.background_(Color.white)
		.clearOnRefresh = false;
		mapButton = Button().states_([
			["map", Color.black, Color.grey],
			["map", Color.black, Color.green(alpha:0.2)]
		])
		.action_({arg button;
			~playerStreamButtonDict.put(expectedPlayerName, button.value.asBoolean)
		})
		.doAction
		.minHeight_(40)
		.maxWidth_(70);
		~playerHostLabels.put(expectedPlayerName, hostLabel);
		~playerPathLabels.put(expectedPlayerName, pathLabel);
		~playerActivityViews.put(expectedPlayerName, activityView);
		View().layout_(HLayout(playerLabel, hostLabel, pathLabel, activityView, mapButton).spacing_(2).margins_(0));
	};
	~activityRows = ~activityRows ++ [nil]; // add stretchable empty space
	~activityPane = View().layout_(VLayout(*~activityRows).spacing_(2).margins_(0));
	~killSoundPane = Button().states_([["killSound"]]).action_({~runningSynths.do{arg synth; synth.free};});
	~dataPane = StaticText().minHeight_(400);

	v !? { v.destroy };
	v = View(nil, Rect(0, 200, Window.screenBounds.width, 200))
	.layout_(VLayout(~activityPane, ~killSoundPane, ~dataPane).spacing_(2).margins_(0))
	.front
	.alwaysOnTop_(true);

	~loadWebPage = {arg url;
		var command;
		inform("visiting %".format(url));
		command = "osascript -e 'tell application \"Safari\" to set the URL of the front document to %'".format("\"" ++ url ++ "\"");
		command.unixCmd;
	};

	// 'tell application \"System Events\"; tell process \"Safari\"; keystroke \"r\" using {command down}; end tell''

	r = Routine({
		inf.do{arg index;
			var urls;
			urls = [
				"http://www.openbsd.org/cgi-bin/man.cgi",
				"http://www.freebsd.org/cgi/man.cgi",
				"http://www.manpagez.com/man/1/screen/"
			];
			~loadWebPage.value(urls[index%2]);
			3.wait;
		};
	}).play;

	SynthDef('www.openbsd.org', {
		var out;
		out = GVerb.ar(LPF.ar(Pulse.ar(440, SinOsc.kr(0.2).range(0, 1), 440)), roomsize: 20);
		out = out * 0.05;
		Out.ar(0, out);
	}).add;

	SynthDef('www.freebsd.org', {
		var out;
		out = GVerb.ar(LPF.ar(WhiteNoise.ar, SinOsc.kr(2).exprange(660, 1220)), roomsize: 1.5, revTime: 1);
		Out.ar(0, out);
	}).add;

	SynthDef('www.manpagez.com', {
		var out;
		out = LFPulse.ar(SinOsc.ar([220, 1660]));
		out = out * 0.05;
		Out.ar(0, out);
	}).add;

});
)


