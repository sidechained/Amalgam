// If your program deals with guis, and or, saves settings to disk, I would advise to use an Model-View-Controller architecture, and decouple gui code from your model code. Models will be anything that responds to value_ , like Ref, NumberEditor, etc. Controllers will be classes that register to get updates from a model, and then do something when the model is updated, such as Updater.  So, if your models get updated (for instance because you loaded new settings from disk), then your guis will be seamlessly updated, otherwise, in my experience, when the code gets complex and you deal with guis, everything turns to chaos.

// is initialisation of the view dependent on the model?
// A: yes, entirely
// the view should just draw the data in the model
// so why not just pass the model to the view?


// to

MyModel {

	var <playerURLs, noOfSoundProcesses;

	*new {
		^super.new.init;
	}

	init {
		playerURLs = (
			\aidan: [],
			\graham: [],
			\michael: [],
			\robin: []
		);
		noOfSoundProcesses = 3;
	}

	appendURL {arg playerName, url;
		// url must be a symbol
		// shouldn't allow two identical URLs to be added (or if so remove should be removeAll)
		var oldURLS, newURLS;
		oldURLS = playerURLs.at(playerName);
		newURLS = oldURLS.add(url);
		playerURLs.put(playerName, newURLS);
	}

	removeURLAtIndex {arg playerName, urlndex;
		playerURLs.at(playerName).removeAt(urlndex);
	}

}

MyView {

	// refactor so as to draw data in the model

	var mainView, noOfSoundProcesses, urlDisplayWidth, buttonSpacing;
	var playerURLs;

	*new {
		^super.new.init;
	}

	init {
		noOfSoundProcesses = 3; // shouldn't be defined here
		urlDisplayWidth = 200;
		buttonSpacing = 3;
		this.makeMainView;
	}

	makeMainView {
		mainView = View(nil, Rect(0, 0, 800, 200));
		mainView.front.alwaysOnTop_(true);
	}

	update {arg argPlayerURLs;
		var surfPane, siftPane;
		playerURLs = argPlayerURLs;
		surfPane = this.makeSurfPane;
		siftPane = this.makeSiftPane;
		mainView.postln;
		mainView.layout !? {
			mainView.removeAll;
			mainView.layout.destroy;
		};
		mainView.layout_(
			VLayout(surfPane, siftPane).spacing_(0).margins_(0)
		);
	}

	getPlayerNames {
		^playerURLs.keys.asArray.sort;
	}

	makeSurfPane {
		var surfTitle, urlView, urlEntry, surfButtonView, surfRow;
		surfTitle = StaticText().string_("SURF");
		urlView = View().layout_(
			HLayout(
				urlEntry = TextField();
			).spacing_(0).margins_(0)
		);
		surfButtonView = this.makeSurfButtonView(urlEntry);
		surfRow = View().layout_(HLayout(urlView, surfButtonView).spacing_(0).margins_(0));
		^View().layout_(VLayout(surfTitle, surfRow).spacing_(0).margins_(0));
	}

	makeSurfButtonView {arg urlEntry;
		var playerButtons, allButton, rowElements;
		playerButtons = this.getPlayerNames.collect{arg playerName;
			var playerInitial;
			playerInitial = playerName.asString.first;
			Button().states_([
				[playerInitial, Color.white, Color.red(alpha:0.2)]
			])
			.action_({
				this.changed(\addURL, playerName, urlEntry.string);
			});
		};
		allButton = Button().states_([
			["all", Color.white, Color.red(alpha:0.2)]
		])
		.action_({
			playerButtons.do{arg playerButton; playerButton.doAction}; // press all surf buttons
		});
		rowElements = playerButtons ++ [allButton];
		^View().layout_(HLayout(*rowElements).spacing_(buttonSpacing).margins_(0));
	}

	makeSiftPane {
		var siftTitle, siftPlayerRows, siftRow, siftPane;
		siftTitle = StaticText().string_("SIFT");
		siftPlayerRows = this.getPlayerNames.collect{arg playerName;
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
		urlRows = playerURLs.at(playerName).collect{arg url, urlIndex; this.makeSiftURLRow(playerName, url, urlIndex) };
		^View().layout_(VLayout(*[playerTitle] ++ urlRows).spacing_(0).margins_(0));
	}

	makeSiftURLRow {arg playerName, url, urlIndex;
		var urlLabel, siftButtonView;
		urlLabel = StaticText()
		.string_(url)
		.maxWidth_(urlDisplayWidth)
		.minWidth_(urlDisplayWidth);
		siftButtonView = this.makeSiftStreamButtonView(playerName, urlIndex);
		^View().layout_(HLayout(urlLabel, siftButtonView).spacing_(0).margins_(0));
	}

	makeSiftStreamButtonView {arg playerName, urlIndex;
		var siftStreamButtons, removeButton;
		siftStreamButtons = this.getPlayerNames.collect{arg playerNameForButton;
			var playerInitial, playerStreamButtons, playerStreamButtonRow;
			playerInitial = playerNameForButton.asString.first;
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
			["remove", Color.white, Color.red(alpha:0.2)]
		])
		.action_({
			this.changed(\removeURL, playerName, urlIndex);
		});
		^View().layout_(
			HLayout(*siftStreamButtons ++ [removeButton]
		).spacing_(buttonSpacing).margins_(0));
	}

	// action funcs:

	onRemoveButtonPress {
		// remove this row
	}

}

MyController {

	var model, view;

	// keeps references to model and view classes

	// Controllers will be classes that register to get updates from a model
	// and then do something when the model is updated, such as Updater

	*new {
		^super.new.init;
	}

	init {
		model = MyModel();
		view = MyView();
		view.update(model.playerURLs);
		view.addDependant({arg object, command, item1, item2;
			if (command == \addURL) {
				var playerName, url;
				playerName = item1;
				url = item2;
				this.addURL(playerName, url);
			};
			if (command == \removeURL) {
				var playerName, urlIndex;
				playerName = item1;
				urlIndex = item2;
				this.removeURL(playerName, urlIndex);
			};
		});
	}

	// shouldn't the data the view uses be taken from the model?

	addURL {arg playerName, url;
		model.appendURL(playerName, url);
		view.update(model.playerURLs);
	}

	removeURL {arg playerName, urlIndex;
		model.removeURLAtIndex(playerName, urlIndex);
		view.update(model.playerURLs);
	}

}