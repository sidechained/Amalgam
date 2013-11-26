// webscore
// orchestrate web pages loading on one machine
// visualise a routine
// once I have such a routine I can focus on the data coming from the apacket analyser

// TODO:
// - call refresh from current position routine
// - monitor start and end of loading for a single website (draw a block)
// - when addStream draw 1 constantly in website's colour, when removeStream stop drawing

(
~oscDict = ();
~oscPaths = ['/stream'/*, '/env', '/removeStream', '/sourcePort', '/destPort', '/response', '/packetLength'*/];

~oscFuncs !? { ~oscFuncs.do{arg oscFunc; oscFunc.free} };
~oscFuncs = ~oscPaths.collect{arg oscPath;
	OSCFunc({arg msg;
		~oscDict.put(msg[0], msg[3]);
	}, oscPath);
};

~load = {arg url;
	var command;
	inform("visiting %".format(url));
	command = "osascript -e 'tell application \"Safari\" to set the URL of the front document to %'".format("\"" ++ url ++ "\"");
	command.unixCmd;
};

// array of which websites will play and when
~routineArray = [
	(urlToVisit: "http://www.wikimedia.org", waitTime: 100)/*,
	(urlToVisit: "http://www.wikileaks.org", waitTime: 3.5),
	(urlToVisit: "http://www.wikipedia.org", waitTime: 8),*/
];
~routineLength = ~routineArray.collect{arg event; event.waitTime}.sum;

~currentPosition = 0;
~uWidth = Window.screenBounds.width;

~makeEventView = {arg labelString, drawFunc;
	// makes a row
	var label, view, parameter;
	label = StaticText().string_(labelString).maxWidth_(100);
	view = UserView()
	.animate_(true)
	.clearOnRefresh_(true)
	.background_(Color.white)
	.drawFunc_({
		var waitTimeAccumulator;
		waitTimeAccumulator = 0;
		// no need to draw these every time
		~routineArray.do{arg dict, index;
			var currentXPos, eventXPos;
			eventXPos = waitTimeAccumulator.linlin(0, ~routineLength, 0, v.bounds.width);
			Pen.line(eventXPos@0, eventXPos@view.bounds.height);
			Pen.strokeColor_(Color.red);
			Pen.width_(3);
			Pen.stroke;
			currentXPos = ~currentPosition.linlin(0, 1, 0, view.bounds.width);
			Pen.line(currentXPos@0, currentXPos@view.bounds.height);
			Pen.strokeColor_(Color.black);
			Pen.stroke;
			waitTimeAccumulator = waitTimeAccumulator + dict.waitTime;
		};
	});
	View().layout_(HLayout(*[label,view]).spacing_(0).margins_(0));
};

~makeOscPathView = {arg oscPath, drawFunc;
	// makes a row
	var label, view, parameter;
	parameter = ~oscDict.at(oscPath);
	label = StaticText().string_(oscPath).maxWidth_(100);
	view = UserView()
	.animate_(true)
	.clearOnRefresh_(false)
	.background_(Color.white)
	.drawFunc_({
		var currentXPos, strokeColor;
		// only draw if value existing in dict
		~oscDict.at(oscPath) !? {
			strokeColor = Color.red(alpha: ~oscDict.at(oscPath).linlin(0, 1, 0.2, 1));
			currentXPos = ~currentPosition.linlin(0, 1, 0, view.bounds.width);
			Pen.line(currentXPos@0, currentXPos@view.bounds.height);
			Pen.strokeColor_(strokeColor);
			Pen.stroke;
		}
	});
	View().layout_(HLayout(*[
		label,
		view
	]).spacing_(0).margins_(0));
};

~eventView = ~makeEventView.value(\events, ~oscEventDrawFunc);
~pathViews = ~oscPaths.collect{arg oscPath; ~makeOscPathView.value(oscPath, ~oscPathDrawFunc); };

v = View(nil, Rect(0, 0, ~uWidth, 200))
.layout_(VLayout(*[~eventView] ++ ~pathViews).spacing_(1).margins_(0))
.front
.alwaysOnTop_(true);

// routine for current position:
Routine({
	var waitTime, iterations, startTime;
	waitTime = 1/60; // default framerate
	iterations = ~routineLength/waitTime;
	// start marking time:
	startTime = Main.elapsedTime;
	iterations.do{arg i;
		~currentPosition = (Main.elapsedTime - startTime) / ~routineLength;
		waitTime.wait;
	}
}).play(AppClock);

// routine to load the websites
Routine({
	~routineArray.do{arg dict;
		~load.value(dict.urlToVisit.postln);
		dict.waitTime.wait;
	};
}).play(AppClock);



// check:
/*Routine({
inf.do {
~oscDict.postln;
0.5.wait;
}
}).play*/

)

