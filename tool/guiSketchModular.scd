(
~makeMainView = {
	var surfPane, siftPane, mainView;
	surfPane = ~makeSurfPane.value;
	siftPane = ~makeSiftPane.value;
	mainView !? { mainView.destroy };
	mainView = View(nil, Rect(0, 0, 800, 400)).layout_(
		VLayout(surfPane, siftPane).spacing_(0).margins_(0)
	);
	mainView.front.alwaysOnTop_(true);
};

~makeSurfPane = {
	var surfTitle, urlEntry, surfButtonView, surfRow;
	surfTitle = StaticText().string_("SURF");
	urlEntry = TextField()
	.maxWidth_(~urlDisplayWidth);
	surfButtonView = ~makeSurfButtonView.value;
	surfRow = View().layout_(HLayout(urlEntry, surfButtonView).spacing_(0).margins_(0));
	View().layout_(VLayout(surfTitle, surfRow).spacing_(0).margins_(0));
};

~makeSurfButtonView = {
	var surfButtons, allButton;
	surfButtons = ~playerNames.collect{arg playerName;
		var playerInitial;
		playerInitial = playerName.asString.first;
		Button().states_([
			[playerInitial, Color.white, Color.red(alpha:0.2)]
		])
		.action_({
			//~addURL.value(playerName, ~urlEntry.string);
		});
	};
	allButton = Button().states_([
		["all", Color.white, Color.red(alpha:0.2)],
		["all", Color.white, Color.green(alpha:0.2)]
	])
	.action_({
		~playerNames.do{arg playerName;
			//~addURL.value(playerName, ~urlEntry.string);
		};
	});
	surfButtons = surfButtons ++ [allButton];
	View().layout_(HLayout(*surfButtons).spacing_(~buttonSpacing).margins_(0));
};


~makeSiftPane = {
	var siftTitle, siftPlayerRows, siftRow, siftPane;
	siftTitle = StaticText().string_("SIFT");
	siftPlayerRows = ~playerNames.collect{arg playerName;
		~makeSiftPlayerRow.value(playerName);
	};
	siftRow = View().layout_(HLayout(*~surfRowElements));
	siftPane = View().layout_(
		VLayout(*[siftTitle] ++ siftPlayerRows)
		.spacing_(0)
		.margins_(0)
	);
};

~makeSiftPlayerRow = {arg playerName;
	var playerTitle, urlRows;
	playerTitle = StaticText()
	.string_(playerName.asString ++ "'s web activity")
	.background_(Color.white);
	urlRows = ~urlDict.at(playerName).collect{arg url; ~makeSiftURLRow.value(url) };
	View().layout_(VLayout(*[playerTitle] ++ urlRows).spacing_(0).margins_(0));
};

~makeSiftURLRow = {arg url;
	var urlLabel, siftButtonView;
	urlLabel = StaticText()
	.string_(url)
	.maxWidth_(~urlDisplayWidth)
	.minWidth_(~urlDisplayWidth);
	siftButtonView = ~makeSiftStreamButtonView.value;
	View().layout_(HLayout(urlLabel, siftButtonView).spacing_(0).margins_(0));
};

~makeSiftStreamButtonView = {
	var siftStreamButtons, removeButton;
	siftStreamButtons = ~playerNames.collect{arg playerName;
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
	removeButton = Button().states_([
		["remove", Color.white, Color.red(alpha:0.2)],
		["remove", Color.white, Color.green(alpha:0.2)]
	])
	.action_({

	});
	View().layout_(
		HLayout(*siftStreamButtons ++ [removeButton]
	).spacing_(~buttonSpacing).margins_(0));
};

// init

~playerNames = [\aidan, \graham, \michael, \robin];
~noOfSoundProcesses = 3;
~urlDict = ();
~playerNames.do{arg playerName; ~urlDict.put(playerName, ["wikipedia"])};
~urlDisplayWidth = 200;
~buttonSpacing = 3;

~makeMainView.value
)
