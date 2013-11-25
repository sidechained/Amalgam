// GUI Layout

// SURFER
// surferTitle
// urlEntry, HLayout(a, g, m, r, all)
// VLayout(surferTitle)

// SIFTER
// sifterTitle
// per player:
// - playerTitle
// per url:
// -- urlRow: HLayout(urlLabel,
// HLayout([a0, a1, a2], [g0, g1, g2], [m0, m1, m2], [r0, r1, r2], [remove])
//
// )

// MAIN
// VLayout(surfer, sifter)

AmalgamGUI {

	var playerNames, noOfSoundProcesses, urlDict, urlDisplayWidth, buttonSpacing;

	*new {
		^super.new.init;
	}

	init {
		playerNames = [\aidan, \graham, \michael, \robin];
		noOfSoundProcesses = 3;
		urlDict = ();
		playerNames.do{arg playerName; urlDict.put(playerName, ["wikipedia"])};
		urlDisplayWidth = 200;
		buttonSpacing = 3;
		this.makeMainView;
	}

	makeMainView {
		var surfPane, siftPane, mainView;
		surfPane = this.makeSurfPane;
		siftPane = this.makeSiftPane;
		mainView !? { mainView.destroy };
		mainView = View(nil, Rect(0, 0, 800, 200)).layout_(
			VLayout(surfPane, siftPane).spacing_(0).margins_(0)
		);
		mainView.front.alwaysOnTop_(true);
	}

	makeSurfPane {
		var surfTitle, urlEntry, surfButtonView, surfRow;
		surfTitle = StaticText().string_("SURF");
		urlEntry = View().layout_(
			HLayout(
				TextField();
			).spacing_(0).margins_(0)
		);
		surfButtonView = this.makeSurfButtonView(urlEntry);
		surfRow = View().layout_(HLayout(urlEntry, surfButtonView).spacing_(0).margins_(0));
		^View().layout_(VLayout(surfTitle, surfRow).spacing_(0).margins_(0));
	}

	makeSurfButtonView {arg urlEntry;
		var surfButtons, allButton;
		surfButtons = playerNames.collect{arg playerName;
			var playerInitial;
			playerInitial = playerName.asString.first;
			Button().states_([
				[playerInitial, Color.white, Color.red(alpha:0.2)]
			])
			.action_({
				this.addURL(playerName, urlEntry.string);
			});
		};
		allButton = Button().states_([
			["all", Color.white, Color.red(alpha:0.2)],
			["all", Color.white, Color.green(alpha:0.2)]
		])
		.action_({
			this.addAllURL(urlEntry.string);
		});
		surfButtons = surfButtons ++ [allButton];
		^View().layout_(HLayout(*surfButtons).spacing_(buttonSpacing).margins_(0));
	}


	makeSiftPane {
		var siftTitle, siftPlayerRows, siftRow, siftPane;
		siftTitle = StaticText().string_("SIFT");
		siftPlayerRows = playerNames.collect{arg playerName;
			this.makeSiftPlayerRow(playerName);
		};
		^View().layout_(
			VLayout(*[siftTitle] ++ siftPlayerRows)
			.spacing_(0)
			.margins_(0)
		);
	}

	makeSiftPlayerRow {arg playerName;
		var playerTitle, urlRows;
		playerTitle = StaticText()
		.string_(playerName.asString ++ "'s web activity")
		.background_(Color.white);
		urlRows = urlDict.at(playerName).collect{arg url; this.makeSiftURLRow(url) };
		^View().layout_(VLayout(*[playerTitle] ++ urlRows).spacing_(0).margins_(0));
	}

	makeSiftURLRow {arg url;
		var urlLabel, siftButtonView;
		urlLabel = StaticText()
		.string_(url)
		.maxWidth_(urlDisplayWidth)
		.minWidth_(urlDisplayWidth);
		siftButtonView = this.makeSiftStreamButtonView;
		^View().layout_(HLayout(urlLabel, siftButtonView).spacing_(0).margins_(0));
	}

	makeSiftStreamButtonView {
		var siftStreamButtons, removeButton;
		siftStreamButtons = playerNames.collect{arg playerName;
			var playerInitial, playerStreamButtons, playerStreamButtonRow;
			playerInitial = playerName.asString.first;
			playerStreamButtons = noOfSoundProcesses.collect{arg soundProcessIndex;
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
			this.onRemoveButtonPress;
		});
		^View().layout_(
			HLayout(*siftStreamButtons ++ [removeButton]
		).spacing_(buttonSpacing).margins_(0));
	}

	// action funcs:

	onRemoveButtonPress {
		// remove this row
	}

	addURL {arg playerName, url;
		var urlRow;
		urlRow = this.makeSiftURLRow(url);
		// where to insert it? append it?
	}

	addAllURL {arg urlEntry;
		playerNames.do{arg playerName;
			//this.addURL(playerName, url);
		};
	}

}