// collaborative browsing

// TODO
// 'missing value' error
// set min and max refresh time bounds
// add ability to refresh by hand

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
// - DON'T FORGET TO DISABLE CACHING
// - NEED TO TEST COMBO OF WIFI AND WIRED NETWORK WORKS
// - DON'T MAKE GUI UNTIL API IS DONE

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

// 5. SYNTHGUI's

(
// main
~autoRefreshTime = 1;
~initSafari.value; // takes time + how to do this in screen space 2?
~startRefreshing.value; //
~setAutoRefreshTime.value(1);
~stopRefreshing.value;
)

(
// GUI

// SINGLE PLAYER FUNCTIONS:
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

~setAutoRefreshTime = {arg autoRefreshTime;

	~autoRefreshTime = autoRefreshTime;
};

// COLLABORATIVE FUNCTIONS:

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

/*~getRefreshState = {
~playerDataSpaces.at(~myName, \refreshState);
};

~getRefreshRate = {
~playerDataSpaces.at(~myName, \refreshRate);
};*/

// GUI FUNCTIONS:

~makeRefreshRow = {arg playerName;
	var playerNameLabel, urlLabel, refreshButton, refreshTime;
	playerNameLabel = StaticText().string_(playerName).background_(Color.white);
	urlLabel = StaticText().string_("nothingyet").background_(Color.white);
	refreshButton = Button()
	.states_([
		["start", Color.black, Color.white],
		["stop", Color.black, Color.green(alpha:0.2)]
	])
	.action_({arg button;
		~setRefreshState.value(playerName, button.value.asBoolean);
	});
	refreshTime = NumberBox().minWidth_(50)
	.value_(~autoRefreshTime)
	.action_({arg numberBox;
		~setRefreshRate.value(playerName, numberBox.value);
	});
	View().layout_(HLayout(
		[playerNameLabel, stretch: ~stretch[0]],
		[urlLabel, stretch: ~stretch[1]],
		[refreshButton, stretch: ~stretch[2]],
		[refreshTime, stretch: ~stretch[3]]
	));
};

~makeCollaborativeGUI = {
	var clockGUI, titleRow, refreshRows;
	~onlineColor = Color.green(alpha: 0.3);
	~offlineColor = Color.black;
	clockGUI = ~makeClockGUI.value;
	titleRow = ~makeTitleRow.value;
	refreshRows = ~expectedPlayerNames.collect({arg expectedPlayerName;
		~makeRefreshRow.value(expectedPlayerName);
	});
	View(nil, Rect(0, 0, 800, 400)).layout_(VLayout(*[clockGUI, titleRow] ++ refreshRows));
};

~makeTitleRow = {
	var playerTitle, urlTitle, refreshTitle, refreshTimeTitle;
	playerTitle = StaticText().string_("player:");
	urlTitle = StaticText().string_("URL:");
	refreshTitle = StaticText().string_("refresh:");
	refreshTimeTitle = StaticText().string_("refresh time:");
	View().layout_(HLayout(
		[playerTitle, stretch: ~stretch[0]],
		[urlTitle, stretch: ~stretch[1]],
		[refreshTitle, stretch: ~stretch[2]],
		[refreshTimeTitle, stretch: ~stretch[3]]
	));
};

~makeClockGUI = {
	var slaveMasterButton, startStopButton, clockDisplay;
	slaveMasterButton = Button()
	.states_([["master"], ["slave"]])
	.action_({arg button;
		if (button.value == 1) {
			//~isClockMaster = true;
			startStopButton.states_([["start"],["stop"]])
		} {
			//~isClockMaster = false;
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
	.string_("00:00")
	.minSize_(200@40).front;
	View().layout_(HLayout(slaveMasterButton, startStopButton, clockDisplay));
};

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

~initNode = {
	var me;
	\initNode.postln;
	~myNode.register(~myName);
	~myNode.addrBook.addDependant({arg addrBook, what, who;
		case
		{ what == \registeredName } {
			if ( who.name == ~myName ) {
				defer {
					var playerNameLabel, rowIndex, playerNameLabelColumnIndex;
					playerNameLabelColumnIndex = 0;
					rowIndex = ~expectedPlayerNames.indexOf(~myName);
					playerNameLabel = ~collaborativeGUI.children[rowIndex + 2].children[playerNameLabelColumnIndex];
					playerNameLabel.background_(~onlineColor);
				};
			};
		}
		{ what == \wentOffline } {
			if ( who.name == ~myName ) {
				defer {
					var playerNameLabel, rowIndex, playerNameLabelColumnIndex;
					playerNameLabelColumnIndex = 0;
					rowIndex = ~expectedPlayerNames.indexOf(~myName);
					playerNameLabel = ~collaborativeGUI.children[rowIndex + 2].children[playerNameLabelColumnIndex];
					playerNameLabel.background_(~offlineColor);
				};
			};
		};
	});
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
				var clockGUI;
				clockGUI = ~collaborativeGUI.children[0].children[2];
				clockGUI.string_(displayString);
			};
		};
	});
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
				var incomingName, rowIndex, playerNameToRefresh, refreshButton, refreshButtonColumnIndex;
				refreshButtonColumnIndex = 2;
				rowIndex = ~expectedPlayerNames.indexOf(expectedPlayerName);
				refreshButton = ~collaborativeGUI.children[rowIndex + 1].children[refreshButtonColumnIndex];
				// + 1 here to account for title row
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
				var incomingName, playerRowIndex, playerNameToRefresh, refreshTimeBox, refreshTimeColumnIndex;
				refreshTimeColumnIndex = 3;
				playerRowIndex = ~expectedPlayerNames.indexOf(expectedPlayerName);
				refreshTimeBox = ~collaborativeGUI.children[playerRowIndex + 1].children[refreshTimeColumnIndex];
				// + 1 here to account for title row
				defer { refreshTimeBox.value_(value); };
				// perform action if me:
				if (expectedPlayerName == ~myName) {
					~autoRefreshTime = value;
				};
			}
		});
	};

	// gui:
	~myName = \graham;
	~expectedPlayerNames = [\aidan, \graham, \michael, \robin];
	~stretch = [3, 6, 2, 1];
	~autoRefreshTime = 1;
	~collaborativeGUI !? { ~collaborativeGUI.destroy };
	~collaborativeGUI = ~makeCollaborativeGUI.value.front;
	~isClockMaster = false;
	~myNode = NMLDecentralisedNode(doWhenMeAdded: ~initNode ); // survive command period
)

// test
~playerDataSpaces.at(\aidan).put('setRefreshState', true);
~playerDataSpaces.at(\aidan).put('setRefreshState', false);

~playerDataSpaces.at(\graham).put('setRefreshState', true);
~playerDataSpaces.at(\graham).put('setRefreshState', false);

~playerDataSpaces.at(\aidan).put('setRefreshRate', 1);
~playerDataSpaces.at(\aidan).put('setRefreshRate', 3);

~playerDataSpaces.at(\graham).put('setRefreshRate', 1);
~playerDataSpaces.at(\graham).put('setRefreshRate', 3);

(
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
)

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

t_trig
s.boot

Ndef(\test, {arg freq = 444; SinOsc.ar(freq) }).play
Ndef(\test).set(\freq, 888)

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
)