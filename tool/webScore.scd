// webscore
// orchestrate web pages loading on one machine
// visualise a routine
// once I have such a routine I can focus on the data coming from the apacket analyser

(
~load = {arg url;
	var command;
	inform("visiting %".format(url));
	command = "osascript -e 'tell application \"Safari\" to set the URL of the front document to %'".format("\"" ++ url ++ "\"");
	command.unixCmd;
};

// array of which websites will play and when
~routineArray = [
	(urlToVisit: "http://www.wikimedia.org", waitTime: 2),
	(urlToVisit: "http://www.wikileaks.org", waitTime: 3.5),
	(urlToVisit: "http://www.wikipedia.org", waitTime: 8),
];
~routineLength = ~routineArray.collect{arg event; event.waitTime}.sum;

~currentPosition = 0;
u = UserView(nil, Rect(0, 0, 800, 20)).drawFunc_({
	var currentXPos, waitTimeAccumulator;
	waitTimeAccumulator = 0;
	~routineArray.do{arg dict, index;
		var eventXPos;
		eventXPos = waitTimeAccumulator.linlin(0, ~routineLength, 0, u.bounds.width);
		Pen.line(eventXPos@0, eventXPos@u.bounds.height);
		Pen.strokeColor_(Color.red);
		Pen.width_(3);
		Pen.stroke;
		waitTimeAccumulator = waitTimeAccumulator + dict.waitTime;
	};
	currentXPos = ~currentPosition.linlin(0, 1, 0, u.bounds.width);
	Pen.line(currentXPos@0, currentXPos@u.bounds.height);
	Pen.strokeColor_(Color.black);
	Pen.stroke;
});
u.animate_(true);
u.front.alwaysOnTop_(true);

// routine for current position:
r = Routine({
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
)

