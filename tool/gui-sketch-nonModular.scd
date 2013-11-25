// SURFER SIFTER SOUNDER

//playerLabel = StaticText().string_(playerInitial).align_(\center);

(
// functions

~addURL = {arg playerName, url;
	var replace, streamRow;
	replace = ~urlDict.at(playerName).add(url);
	~urlDict.put(playerName, replace);
	~urlDict.postln;
	streamRow = ~playerNames.indexOf(playerName);
	// append a stream row
	// lookup
};

~playerNames = [\aidan, \graham, \michael, \robin];
~noOfSoundProcesses = 3;
~urlDict = ();
~playerNames.do{arg playerName; ~urlDict.put(playerName, ["wikipedia"])};
~urlDisplayWidth = 200;
~buttonSpacing = 3;
// SURF
// SURF TITLE
~surfTitle = StaticText().string_("SURF");
// SURF ROW
~urlEntry = TextField()
.maxWidth_(~urlDisplayWidth);
~surfButtons = ~playerNames.collect{arg playerName;
	var playerInitial;
	playerInitial = playerName.asString.first;
	Button().states_([
		[playerInitial, Color.white, Color.red(alpha:0.2)]
	])
	.action_({
		~addURL.value(playerName, ~urlEntry.string);
	});
};
~allButton = Button().states_([
	["all", Color.white, Color.red(alpha:0.2)],
	["all", Color.white, Color.green(alpha:0.2)]
])
.action_({
	~playerNames.do{arg playerName;
		~addURL.value(playerName, ~urlEntry.string);
	};
});
~surfButtons = ~surfButtons ++ [~allButton];
~surfButtonView = View().layout_(HLayout(*~surfButtons).spacing_(~buttonSpacing).margins_(0));
// SURF PANE
~surfRow = View().layout_(HLayout(~urlEntry, ~surfButtonView).spacing_(0).margins_(0));
~surfPane = View().layout_(VLayout(~surfTitle, ~surfRow).spacing_(0).margins_(0));

// SIFT
// SIFT TITLE
~siftTitle = StaticText().string_("SIFT");
// SIFT PLAYER ROWS
// - each row consists of a title plus a number of stream rows
~siftPlayerRows = ~playerNames.collect{arg playerName;
	~surfTitle = StaticText()
	.string_(playerName.asString ++ "'s web activity")
	.background_(Color.white);
	// stream row
	~streamRows = ~urlDict.at(playerName).collect{arg url;
		~streamLabel = StaticText()
		.string_(url)
		.maxWidth_(~urlDisplayWidth)
		.minWidth_(~urlDisplayWidth);
		~siftStreamButtons = ~playerNames.collect{arg playerName;
			var playerInitial, playerStreamButtons, playerStreamButtonRow;
			playerInitial = playerName.asString.first;
			playerStreamButtons = ~noOfSoundProcesses.collect{arg soundProcessIndex;
				Button().states_([
					[soundProcessIndex, Color.white, Color.red(alpha:0.2)],
					[soundProcessIndex, Color.white, Color.green(alpha:0.2)]
				])
				.maxWidth_(30);
			};
			playerStreamButtonRow = View().layout_(
				HLayout(*playerStreamButtons)
				.spacing_(0)
				.margins_(0)
			);
			View().layout_(VLayout(playerStreamButtonRow).spacing_(0).margins_(0));
		};
		~removeButton = Button().states_([
			["remove", Color.white, Color.red(alpha:0.2)],
			["remove", Color.white, Color.green(alpha:0.2)]
		])
		.action_({

		});
		~siftButtonView = View().layout_(
			HLayout(*~siftStreamButtons ++ [~removeButton]
		).spacing_(~buttonSpacing).margins_(0));
		View().layout_(HLayout(~streamLabel, ~siftButtonView).spacing_(0).margins_(0));
	};
	View().layout_(VLayout(*[~surfTitle] ++ ~streamRows).spacing_(0).margins_(0));
};
// SIFT PANE
~siftRow = View().layout_(HLayout(*~surfRowElements));
~siftPane = View().layout_(
	VLayout(*[~siftTitle] ++ ~siftPlayerRows)
	.spacing_(0)
	.margins_(0)
);

// MAIN
~mainView !? { ~mainView.destroy };
~mainView = View(nil, Rect(0, 0, 800, 400)).layout_(
	VLayout(~surfPane, ~siftPane).spacing_(0).margins_(0)
);
~mainView.front.alwaysOnTop_(true);
)

// PLAYERS
// first off only headers will be drawn

// SIFT ROW
