// SURFER

// now networked
// orchestrate the visiting of websites across multiple computers
// will this be done with routines, a timeline view?
// would be good if each player had a stock of URLs, which they could add to on the fly
//
// live browsing?

(
// simple GUI for entering/choosing URLs
// open safari (might need to wait a while here) // Q: how to do this in separate screenspace
"osascript -e 'tell application \"Safari\" to activate'".unixCmd;
t = TextField();
p = PopUpMenu();
p.action_({arg popUpMenu;
	var command, url;
	url = "\"" ++ popUpMenu.item ++ "\"";
	inform("visiting %".format(url));
	command = "osascript -e 'tell application \"Safari\" to set the URL of the front document to %'".format(url);
	command.unixCmd;
});
v !? { v.destroy };
v = View(nil, Rect(0, 0, 500, 20)).layout_(VLayout(*[p, t]));
v.front.alwaysOnTop_(true);
p.items = ["http://www.wikipedia.org", "http://www.wikileaks.org"];
t.keyDownAction_({arg textField, key;
	var returnKeyCode;
	returnKeyCode = 13;
	if (key.ascii == returnKeyCode) {
		p.items = p.items.add(textField.string);
	};
});
)

(
// networked version
// Q: should look for four players, or just discover anyone?
// potential issue with using wifi and en1 at same time
/*n = NMLDecentralisedNode();
n.register(\lappy);*/
var playerNames, playerRows;
playerNames = ["michael", "graham", "aidan", "robin"];
playerRows = playerNames.collect{arg playerName;
	var button, staticText;
	button = Button().states_([[playerName, Color.white, Color.red(alpha:0.1)], [playerName, Color.white, Color.green(alpha:0.1)]]);
	staticText = StaticText();
	staticText.minWidth_(500);
	staticText.background_(Color.blue(alpha: 0.1));
	staticText.string_("hi");
	View().layout_(HLayout(button, staticText))
};
v = View().layout_(VLayout(*playerRows));
v.front.alwaysOnTop_(true);
)



(
var onlineButtonDict, playerNames, myName, myNode;

~init = {
	inform("% joined".format(myName));
	~initVisitFunc.value;
	myNode.addrBook.addDependant(~showOnlineStatus);
	myNode.register(myName);
	defer {
		~mainView !? { ~mainView.destroy };
		~mainView = ~makePlayerRows.value(playerNames);
		~mainView.front.alwaysOnTop_(true);
	}
};

~initVisitFunc = {
	~visitFunc !? {~visitFunc.free};
	~visitFunc = OSCFunc({arg msg;
		var url, command;
		url = msg.drop(1).first;
		url = "\"" ++ url ++ "\"";
		inform("% visiting %".format(myName, url));
		command = "osascript -e 'tell application \"Safari\" to set the URL of the front document to %'".format(url);
		command.unixCmd;
	}, '/visitURL');
};

~makePlayerRows = {arg playerNames;
	var playerRows;
	playerRows = playerNames.collect{arg playerName; ~makePlayerRow.value(playerName); };
	View().layout_(VLayout(*playerRows));
};

~showOnlineStatus = {arg addrBook, what, whoPeer;
	//[what, whoPeer].postln;
	if (what == \registeredName) {
		if (onlineButtonDict.keys.includes(whoPeer.name)) {
			defer {onlineButtonDict.at(myName).value_(1);}
		}
	} {
		if (what == \wentOffline) {
			// never gets here at the moment (mynode kill doesn't work)
			\getsHere.postln;
			if (onlineButtonDict.keys.includes(whoPeer.name)) {
				defer{onlineButtonDict.at(myName).value_(1);};
			}
		};
	};
};

~makePlayerRow = {arg playerName;
	var onlineButton, b1, b2;
	onlineButton = Button().states_([[playerName, Color.white, Color.red(alpha:0.1)], [playerName, Color.white, Color.green(alpha:0.1)]]);
	onlineButtonDict.put(playerName, onlineButton);
	b1 = ~makeURLButton.value("http://www.wikimedia.org");
	b2 = ~makeURLButton.value("http://www.wikipedia.org");
	v = View().layout_(HLayout(onlineButton, b1, b2));
	v.front.alwaysOnTop_(true);
};

~makeURLButton = {arg url;
	Button()
	.states_([[url]])
	.action_({
		var msgToSend;
		msgToSend = [myName, '/visitURL', url];
		inform("sending: %".format(msgToSend));
		myNode.addrBook.sendName(*msgToSend)
	});
};

// main

onlineButtonDict = ();
playerNames = [\grimac, \grilap];
myName = \grilap;
myNode = NMLDecentralisedNode(doWhenMeAdded: ~init);
)

// http://www.wikipedia.org
// useful refs:
// applescripting...
// http://new-supercollider-mailing-lists-forums-use-these.2681727.n2.nabble.com/scripting-scripts-Applescript-td7599506.html#a7599554
// http://hints.macworld.com/article.php?story=20040720011307587

