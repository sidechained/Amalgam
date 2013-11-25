
m = MyModel();
m.addURL(\aidan, 'wikipedia.org');
m.removeURL(\aidan, 'wikipedia.org');
m.playerURLs;

v = MyView();
v.appendURLRow('wikipedia.org');
v.removeURLRow('wikipedia.org');

(
m = MyModel(); v = MyView(); c = MyController(m, v);
)
