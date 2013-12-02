// collaborative browsing

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
// browse/refresh frontmost web page in Safari
// - sonically, will respond to four domains only
// - first visit will be entering URL
// - URL can then be set to refresh automatically (given rate)
// - when refreshing stops, about:blank should appear

// 2. COLLABORATIVE
// - every can start/stop each other's pages, and adjust the timing

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
~tempo = 60; // in bpm
// master will run this:
OSCdef(\clock, {arg msg;
	var currentTime;
	inform("receiving: %".format(msg));
	currentTime = msg[1];
	// need modulo
}, '/clock');
)

(
// slaves will run this:
~clockRoutine !? {~clockRoutine.free}; // prevent multiple clocks
~clockRoutine = Routine({
	var now;
	now = Main.elapsedTime; // do this on startup
	inf.do{
		var currentTime, msgToSend;
		currentTime = Main.elapsedTime - now; // send this
		msgToSend = [\clock, currentTime];
		inform("sending: %".format(msgToSend));
		NetAddr("localhost", 57120).sendMsg(*msgToSend);// broadcast time (local for now)
		// or put in OSCDataSpace
		0.1.wait; // wait time here
	};
}).play(SystemClock) // can run thru cmd + period?
)

OSCFunc.trace(true)

s.quit

/*a = AddrBook();
OSCDataSpace(oscPath: '/collectiveSpace')

OSCDataSpace.addDependant({arg a, b, c, d;
[a, b, c, d].postln;
case
{ what == \clock } { ~currentTime = value }
})*/

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
	// WARN if too low
	// what is the minimum?
	// 1.5 page still gets chance to load
	// 0.5 it doesn't (could play with this)
	~autoRefreshTime = autoRefreshTime;
};

// COLLABORATIVE FUNCTIONS:

~putStartRefreshing = {arg playerName;
	var dataSpace;
	dataSpace = ~playerDataSpaces.at(playerName);
	dataSpace.put(\startRefreshing);
};

~putStopRefreshing = {arg playerName;
	var dataSpace;
	dataSpace = ~playerDataSpaces.at(playerName);
	dataSpace.put(\stopRefreshing);
};

// GUI FUNCTIONS:

~makeRefreshRow = {arg playerName;
	var playerNameLabel, urlLabel, refreshButton, refreshTime;
	playerNameLabel = StaticText().string_(playerName).background_(Color.white);
	urlLabel = StaticText().string_("nothingyet").background_(Color.white);
	refreshButton = Button()
	.states_([
		["refresh", Color.black, Color.white],
		["refresh", Color.black, Color.green(alpha:0.2)]
	])
	.action_({arg button;
		case
		{ button.value == 1 } { ~startRefreshing.value(playerName) }
		{ button.value == 0 } { ~stopRefreshing.value(playerName) }
	});
	refreshTime = NumberBox().minWidth_(50)
	.value_(~autoRefreshTime)
	.action_({arg numberBox;
		var autoRefreshTime;
		autoRefreshTime = numberBox.value;
		~setAutoRefreshTime.value(autoRefreshTime);
	})
	.doAction;
	View().layout_(HLayout(
		[playerNameLabel, stretch: ~stretch[0]],
		[urlLabel, stretch: ~stretch[1]],
		[refreshButton, stretch: ~stretch[2]],
		[refreshTime, stretch: ~stretch[3]]
	));
};

~makeCollaborativeGUI = {
	var titleRow, refreshRows;
	titleRow = ~makeTitleRow.value;
	refreshRows = ~expectedPlayerNames.collect({arg expectedPlayerName;
		~makeRefreshRow.value(expectedPlayerName);
	});
	View(nil, Rect(0, 0, 800, 300)).layout_(VLayout(*[titleRow] ++ refreshRows));
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
		[refreshTimeTitle, stretch: ~stretch[3]
		]
	));
};

~initNode = {
	var me;
	\initNode.postln;
	~myNode.register(~myName);
	~playerDataSpaces = ();
	~expectedPlayerNames.do({arg expectedPlayerName;
		var playerDataSpace;
		playerDataSpace = OSCDataSpace(~myNode.addrBook, ~myNode.me, oscPath: expectedPlayerName);
		~initDependencyHandler.value(expectedPlayerName, playerDataSpace);
		~playerDataSpaces.put(expectedPlayerName, playerDataSpace);
	});
};

~initDependencyHandler = {arg expectedPlayerName, playerDataSpace;
	playerDataSpace.addDependant({arg dataSpace, val, key, value;
		[dataSpace, val, key, value].postln;
		case
		{ key == \setRefreshState } {
			// update GUI
			var incomingName, rowIndex, playerNameToRefresh, refreshButton, refreshButtonColumnIndex;
			refreshButtonColumnIndex = 2;
			rowIndex = ~expectedPlayerNames.indexOf(expectedPlayerName);
			refreshButton = ~collaborativeGUI.children[rowIndex + 1].children[refreshButtonColumnIndex];
			// + 1 here to account for title row
			defer { refreshButton.value_(value.asInt); };
			// perform action if me
			if (expectedPlayerName == ~myName) {
				if (value == true) {
					\startingRefresh.postln;
					~startRefreshing.value;
				} {
					\stoppingRefresh.postln;
					~stopRefreshing.value;
				};
			};
		}
		/*		{ key == \setRefreshRate } {
		// update GUI
		var incomingName, playerRowIndex, playerNameToRefresh, refreshTimeBox, refreshTimeColumnIndex;
		refreshTimeColumnIndex = 3;
		playerRowIndex = ~expectedPlayerNames.indexOf(expectedPlayerName);
		refreshTimeBox = ~collaborativeGUI.children[playerRowIndex + 1].children[refreshTimeColumnIndex];
		// + 1 here to account for title row
		defer { refreshTimeBox.value(value); };
		// perform action if me
		/*			if (expectedPlayerName == ~myName) {
		~autoRefreshTime = value
		};*/
		}*/
	});
};

// gui:
~myName = \graham;
~expectedPlayerNames = [\aidan, \graham, \michael, \robin];
~stretch = [3, 6, 2, 1];
~autoRefreshTime = 1;
~collaborativeGUI !? { ~collaborativeGUI.destroy };
~collaborativeGUI = ~makeCollaborativeGUI.value.front;
~myNode = NMLDecentralisedNode(surviveCmdPeriod: false, doWhenMeAdded: ~initNode );
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


GUI

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