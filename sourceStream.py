(
~sourceDict = ();

~addSource = {arg sourceIP;
	var index;
	index = ~sourceDict.keys.size;
	~sourceDict.put(sourceIP, (index: index, streamDict: ()));
};

~removeSource = {arg sourceIP;
	~sourceDict.removeAt(sourceIP);
};

~addStream = {arg sourceIP, streamKey;
	var streamDict, index;
	streamDict = ~sourceDict.at(sourceIP).streamDict;
	index = streamDict.size;
	streamDict.put(streamKey, (index: index));
};

~removeStream = {arg sourceIP, streamKey;
	~sourceDict.at(sourceIP).streamDict.removeAt(streamKey);
};
)

~addSource.value('128.9.9.1')
~removeSource.value('128.9.9.2')

~addStream.value('128.9.9.1', '1234')
~removeStream.value('128.9.9.1', '1234')

// get source index
~sourceDict.at('128.9.9.1').streamDict.at('5678').index

// get stream index
~sourceDict.at('128.9.9.1').index
