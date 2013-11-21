// SURFER

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

// http://www.wikipedia.org
// useful refs:
// applescripting...
// http://new-supercollider-mailing-lists-forums-use-these.2681727.n2.nabble.com/scripting-scripts-Applescript-td7599506.html#a7599554
// http://hints.macworld.com/article.php?story=20040720011307587
